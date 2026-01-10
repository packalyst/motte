// Package sentinel provides a multi-feature Traefik middleware for access control.
// Features: IP filtering, maintenance mode, robots.txt, header validation, user-agent blocking, time-based access.
package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BlockReason identifies why a request was blocked
type BlockReason int

const (
	BlockReasonIP BlockReason = iota
	BlockReasonUserAgent
	BlockReasonHeader
	BlockReasonTime
	BlockReasonMaintenance
)

// =============================================================================
// Configuration
// =============================================================================

// Config holds the plugin configuration.
type Config struct {
	// IPFilter restricts access by source IP
	IPFilter *IPFilterConfig `json:"ipFilter,omitempty"`

	// Maintenance shows a maintenance page when trigger file exists
	Maintenance *MaintenanceConfig `json:"maintenance,omitempty"`

	// Robots serves a robots.txt response
	Robots *RobotsConfig `json:"robots,omitempty"`

	// Headers validates request headers
	Headers []HeaderConfig `json:"headers,omitempty"`

	// UserAgents blocks requests by user-agent
	UserAgents *UserAgentsConfig `json:"userAgents,omitempty"`

	// TimeAccess restricts access by time of day
	TimeAccess *TimeAccessConfig `json:"timeAccess,omitempty"`

	// ErrorMode determines response for blocked requests: silent, 401, 403, 404, 503
	ErrorMode string `json:"errorMode,omitempty"`
}

// IPFilterConfig configures IP-based filtering.
type IPFilterConfig struct {
	// SourceRange is a list of allowed IP ranges in CIDR notation
	SourceRange []string `json:"sourceRange,omitempty"`
}

// MaintenanceConfig configures maintenance mode.
type MaintenanceConfig struct {
	// Enabled activates maintenance mode
	Enabled bool `json:"enabled,omitempty"`
	// Code is the HTTP status code (default 503)
	Code int `json:"code,omitempty"`
	// Message to display
	Message string `json:"message,omitempty"`
	// Title for the page
	Title string `json:"title,omitempty"`
}

// RobotsConfig configures robots.txt serving.
type RobotsConfig struct {
	// Enabled activates robots.txt handling
	Enabled bool `json:"enabled,omitempty"`
	// ListURL to fetch AI bot list (JSON format)
	ListURL string `json:"listUrl,omitempty"`
	// CacheTTL in seconds for remote list (default 86400 = 24h)
	CacheTTL int `json:"cacheTTL,omitempty"`
	// Disallow paths for all bots
	Disallow []string `json:"disallow,omitempty"`
	// Allow paths for all bots
	Allow []string `json:"allow,omitempty"`
	// Custom raw rules to append
	Custom string `json:"custom,omitempty"`
}

// HeaderConfig configures a header validation rule.
type HeaderConfig struct {
	// Name of the header to check
	Name string `json:"name,omitempty"`
	// Values to match against
	Values []string `json:"values,omitempty"`
	// MatchType: one (any match), all (all required), none (blacklist)
	MatchType string `json:"matchType,omitempty"`
	// Regex pattern to match
	Regex string `json:"regex,omitempty"`
	// Required - if false, missing header is allowed
	Required bool `json:"required,omitempty"`
	// Contains - match as substring
	Contains bool `json:"contains,omitempty"`
}

// UserAgentsConfig configures user-agent blocking.
type UserAgentsConfig struct {
	// Enabled activates user-agent checking
	Enabled bool `json:"enabled,omitempty"`
	// ListURL to fetch crawler list (JSON format from monperrus/crawler-user-agents)
	ListURL string `json:"listUrl,omitempty"`
	// CacheTTL in seconds for remote list (default 86400 = 24h)
	CacheTTL int `json:"cacheTTL,omitempty"`
	// Block specific user-agent patterns (custom additions)
	Block []string `json:"block,omitempty"`
	// Allow specific user-agent patterns (whitelist, overrides block)
	Allow []string `json:"allow,omitempty"`
}

// TimeAccessConfig configures time-based access control.
type TimeAccessConfig struct {
	// Enabled activates time-based checking
	Enabled bool `json:"enabled,omitempty"`
	// AllowRange time range when access is allowed "HH:MM-HH:MM" (e.g., "09:00-18:00")
	AllowRange string `json:"allowRange,omitempty"`
	// DenyRange time range when access is denied "HH:MM-HH:MM" (takes precedence over allow)
	DenyRange string `json:"denyRange,omitempty"`
	// Days of week to apply (empty = all days). Values: mon, tue, wed, thu, fri, sat, sun
	Days []string `json:"days,omitempty"`
	// Timezone for time calculations (default "UTC"). E.g., "Europe/Riga", "America/New_York"
	Timezone string `json:"timezone,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ErrorMode: "403",
	}
}

// =============================================================================
// Error Responses
// =============================================================================

const errorPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>{TITLE} | {CODE}</title>
    <style>body,html{width:100%;height:100%;background-color:#21232a}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%;box-shadow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:"Open Sans",Arial,sans-serif}h1{font-weight:500;line-height:1.1;font-size:36px}h1 small{font-size:68%;font-weight:400;line-height:1;color:#777}.lead{color:silver;font-size:21px;line-height:1.4}.cover{display:table-cell;vertical-align:middle;padding:0 20px}</style>
</head>
<body>
    <div class="cover"><h1>{TITLE} <small>{CODE}</small></h1><p class="lead">{MESSAGE}</p></div>
</body>
</html>`

var errorResponses = map[string]struct {
	code    int
	title   string
	message string
}{
	"401":   {401, "Unauthorized", "Authentication is required to access this resource."},
	"403":   {403, "Access Denied", "You don't have permission to access this resource."},
	"404":   {404, "Not Found", "The requested resource could not be found."},
	"503":   {503, "Service Unavailable", "The service is temporarily unavailable."},
	"error": {403, "Access Denied", "You don't have permission to access this resource."},
}

// getTemplate returns the HTML template for a block reason
func getTemplate(reason BlockReason) string {
	switch reason {
	case BlockReasonIP:
		return templateIPBlocked
	case BlockReasonUserAgent:
		return templateUserAgent
	case BlockReasonHeader:
		return templateHeaderMissing
	case BlockReasonTime:
		return templateTimeAccess
	case BlockReasonMaintenance:
		return templateMaintenance
	default:
		return ""
	}
}

// =============================================================================
// Cache for Remote Lists
// =============================================================================

type remoteCache struct {
	mu        sync.RWMutex
	data      interface{}
	fetchedAt time.Time
	ttl       time.Duration
	url       string
	fetching  bool
}

func newCache(url string, ttlSeconds int) *remoteCache {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	return &remoteCache{
		url: url,
		ttl: ttl,
	}
}

func (c *remoteCache) isValid() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data != nil && time.Since(c.fetchedAt) < c.ttl
}

func (c *remoteCache) get() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

func (c *remoteCache) set(data interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = data
	c.fetchedAt = time.Now()
	c.fetching = false
}

func (c *remoteCache) startFetching() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fetching {
		return false
	}
	c.fetching = true
	return true
}

func (c *remoteCache) fetch(parser func([]byte) interface{}) interface{} {
	if c.url == "" {
		return nil
	}

	// Return cached if valid
	if c.isValid() {
		return c.get()
	}

	// Try to start fetch (only one goroutine fetches)
	if !c.startFetching() {
		// Another fetch in progress, return stale data
		return c.get()
	}

	// Fetch with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.url)
	if err != nil {
		c.mu.Lock()
		c.fetching = false
		c.mu.Unlock()
		return c.get() // Return stale on error
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.mu.Lock()
		c.fetching = false
		c.mu.Unlock()
		return c.get()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.mu.Lock()
		c.fetching = false
		c.mu.Unlock()
		return c.get()
	}

	data := parser(body)
	if data != nil {
		c.set(data)
	} else {
		c.mu.Lock()
		c.fetching = false
		c.mu.Unlock()
	}
	return c.get()
}

// =============================================================================
// Sentinel Middleware
// =============================================================================

// Sentinel is the middleware handler.
type Sentinel struct {
	next   http.Handler
	name   string
	config *Config
	debug  bool

	// Parsed data
	networks     []*net.IPNet
	headerRegex  []*regexp.Regexp
	robotsCache  *remoteCache
	agentsCache  *remoteCache
	blockRegex   []*regexp.Regexp
	allowRegex   []*regexp.Regexp
	timeLocation *time.Location
	timeAllow    *timeRange
	timeDeny     *timeRange
}

// timeRange represents a parsed time range
type timeRange struct {
	startHour   int
	startMinute int
	endHour     int
	endMinute   int
}

// log prints debug messages if debug mode is enabled.
func (s *Sentinel) log(format string, args ...interface{}) {
	if s.debug {
		fmt.Fprintf(os.Stderr, "[sentinel] "+format+"\n", args...)
	}
}

// New creates a new Sentinel middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	debug := os.Getenv("SENTINEL_DEBUG") == "true"

	s := &Sentinel{
		next:   next,
		name:   name,
		config: config,
		debug:  debug,
	}

	// Parse IP networks
	if config.IPFilter != nil {
		for _, cidr := range config.IPFilter.SourceRange {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			// Handle single IPs without CIDR notation
			if !strings.Contains(cidr, "/") {
				if strings.Contains(cidr, ":") {
					cidr += "/128"
				} else {
					cidr += "/32"
				}
			}
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			s.networks = append(s.networks, network)
		}
	}

	// Compile header regex patterns
	for _, h := range config.Headers {
		if h.Regex != "" {
			re, err := regexp.Compile(h.Regex)
			if err != nil {
				s.headerRegex = append(s.headerRegex, nil)
			} else {
				s.headerRegex = append(s.headerRegex, re)
			}
		} else {
			s.headerRegex = append(s.headerRegex, nil)
		}
	}

	// Initialize robots cache
	if config.Robots != nil && config.Robots.Enabled && config.Robots.ListURL != "" {
		s.robotsCache = newCache(config.Robots.ListURL, config.Robots.CacheTTL)
	}

	// Initialize user-agents cache and compile patterns
	if config.UserAgents != nil && config.UserAgents.Enabled {
		if config.UserAgents.ListURL != "" {
			s.agentsCache = newCache(config.UserAgents.ListURL, config.UserAgents.CacheTTL)
		}
		// Compile custom block patterns
		for _, pattern := range config.UserAgents.Block {
			if re, err := regexp.Compile("(?i)" + pattern); err == nil {
				s.blockRegex = append(s.blockRegex, re)
			}
		}
		// Compile custom allow patterns
		for _, pattern := range config.UserAgents.Allow {
			if re, err := regexp.Compile("(?i)" + pattern); err == nil {
				s.allowRegex = append(s.allowRegex, re)
			}
		}
	}

	// Initialize time access config
	if config.TimeAccess != nil && config.TimeAccess.Enabled {
		tz := config.TimeAccess.Timezone
		if tz == "" {
			tz = "UTC"
		}
		loc, err := time.LoadLocation(tz)
		if err != nil {
			loc = time.UTC
		}
		s.timeLocation = loc
		s.timeAllow = parseTimeRange(config.TimeAccess.AllowRange)
		s.timeDeny = parseTimeRange(config.TimeAccess.DenyRange)
	}

	if debug {
		s.log("initialized: ipFilter=%d networks, headers=%d rules, robots=%v, userAgents=%v, timeAccess=%v",
			len(s.networks), len(config.Headers),
			config.Robots != nil && config.Robots.Enabled,
			config.UserAgents != nil && config.UserAgents.Enabled,
			config.TimeAccess != nil && config.TimeAccess.Enabled)
	}

	return s, nil
}

// ServeHTTP implements the http.Handler interface.
func (s *Sentinel) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	s.log("request: %s %s from %s", req.Method, req.URL.Path, req.RemoteAddr)

	// 1. Maintenance check (highest priority)
	if s.checkMaintenance() {
		s.serveMaintenance(rw, req)
		return
	}

	// 2. Robots.txt handling
	if s.config.Robots != nil && s.config.Robots.Enabled && req.URL.Path == "/robots.txt" {
		s.serveRobots(rw, req)
		return
	}

	// 3. IP filter check
	if s.config.IPFilter != nil && len(s.networks) > 0 {
		clientIP := s.getClientIP(req)
		if clientIP == nil || !s.isIPAllowed(clientIP) {
			s.log("IP blocked: %v", clientIP)
			s.blockRequest(rw, req, BlockReasonIP)
			return
		}
	}

	// 4. User-agent check
	if s.config.UserAgents != nil && s.config.UserAgents.Enabled {
		if s.isUserAgentBlocked(req.Header.Get("User-Agent")) {
			s.log("User-Agent blocked: %s", req.Header.Get("User-Agent"))
			s.blockRequest(rw, req, BlockReasonUserAgent)
			return
		}
	}

	// 5. Header validation
	if len(s.config.Headers) > 0 {
		if !s.validateHeaders(req) {
			s.log("Headers validation failed")
			s.blockRequest(rw, req, BlockReasonHeader)
			return
		}
	}

	// 6. Time-based access
	if s.config.TimeAccess != nil && s.config.TimeAccess.Enabled {
		if !s.checkTimeAccess() {
			s.log("Time access denied")
			s.blockRequest(rw, req, BlockReasonTime)
			return
		}
	}

	// All checks passed
	s.next.ServeHTTP(rw, req)
}

// =============================================================================
// Maintenance Mode
// =============================================================================

func (s *Sentinel) checkMaintenance() bool {
	m := s.config.Maintenance
	return m != nil && m.Enabled
}

func (s *Sentinel) serveMaintenance(rw http.ResponseWriter, req *http.Request) {
	m := s.config.Maintenance
	code := m.Code
	if code == 0 {
		code = 503
	}
	title := m.Title
	if title == "" {
		title = "Maintenance"
	}
	message := m.Message
	if message == "" {
		message = "We're currently performing maintenance. Please check back soon."
	}

	// Try custom maintenance template
	html := getTemplate(BlockReasonMaintenance)
	if html == "" {
		// Fallback to generic template
		html = errorPageTemplate
	}
	html = strings.Replace(html, "{CODE}", fmt.Sprintf("%d", code), -1)
	html = strings.Replace(html, "{TITLE}", title, -1)
	html = strings.Replace(html, "{MESSAGE}", message, -1)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Retry-After", "300")
	rw.WriteHeader(code)
	rw.Write([]byte(html))
}

// =============================================================================
// Robots.txt
// =============================================================================

// RobotsBotEntry represents a bot entry from ai-robots-txt JSON.
type RobotsBotEntry struct {
	Name      string `json:"name"`
	UserAgent string `json:"user-agent"`
	Operator  string `json:"operator"`
}

func (s *Sentinel) serveRobots(rw http.ResponseWriter, req *http.Request) {
	var sb strings.Builder
	sb.WriteString("# Generated by Sentinel\n\n")

	// Fetch and process remote AI bot list
	if s.robotsCache != nil {
		data := s.robotsCache.fetch(func(body []byte) interface{} {
			var bots []RobotsBotEntry
			if err := json.Unmarshal(body, &bots); err != nil {
				return nil
			}
			return bots
		})
		if bots, ok := data.([]RobotsBotEntry); ok {
			for _, bot := range bots {
				ua := bot.UserAgent
				if ua == "" {
					ua = bot.Name
				}
				if ua != "" {
					sb.WriteString(fmt.Sprintf("User-agent: %s\nDisallow: /\n\n", ua))
				}
			}
		}
	}

	// Default rules
	sb.WriteString("User-agent: *\n")
	for _, path := range s.config.Robots.Disallow {
		sb.WriteString(fmt.Sprintf("Disallow: %s\n", path))
	}
	for _, path := range s.config.Robots.Allow {
		sb.WriteString(fmt.Sprintf("Allow: %s\n", path))
	}
	sb.WriteString("\n")

	// Custom rules
	if s.config.Robots.Custom != "" {
		sb.WriteString("# Custom rules\n")
		sb.WriteString(s.config.Robots.Custom)
		sb.WriteString("\n")
	}

	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Header().Set("Cache-Control", "public, max-age=86400")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(sb.String()))
}

// =============================================================================
// IP Filter
// =============================================================================

func (s *Sentinel) getClientIP(req *http.Request) net.IP {
	// CF-Connecting-IP (Cloudflare)
	if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(cfIP)); ip != nil {
			return ip
		}
	}

	// X-Forwarded-For
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
				return ip
			}
		}
	}

	// X-Real-IP
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
			return ip
		}
	}

	// RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return net.ParseIP(req.RemoteAddr)
	}
	return net.ParseIP(host)
}

func (s *Sentinel) isIPAllowed(ip net.IP) bool {
	for _, network := range s.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// =============================================================================
// User-Agent Blocking
// =============================================================================

// CrawlerEntry represents a bot from monperrus/crawler-user-agents JSON.
type CrawlerEntry struct {
	Pattern  string   `json:"pattern"`
	URL      string   `json:"url"`
	Instances []string `json:"instances"`
}

func (s *Sentinel) isUserAgentBlocked(ua string) bool {
	if ua == "" {
		return false
	}

	// Check allow list first (whitelist)
	for _, re := range s.allowRegex {
		if re.MatchString(ua) {
			return false
		}
	}

	// Check custom block patterns
	for _, re := range s.blockRegex {
		if re.MatchString(ua) {
			return true
		}
	}

	// Check remote crawler list
	if s.agentsCache != nil {
		data := s.agentsCache.fetch(func(body []byte) interface{} {
			var crawlers []CrawlerEntry
			if err := json.Unmarshal(body, &crawlers); err != nil {
				return nil
			}
			// Compile patterns
			var compiled []*regexp.Regexp
			for _, c := range crawlers {
				if re, err := regexp.Compile(c.Pattern); err == nil {
					compiled = append(compiled, re)
				}
			}
			return compiled
		})
		if patterns, ok := data.([]*regexp.Regexp); ok {
			for _, re := range patterns {
				if re.MatchString(ua) {
					return true
				}
			}
		}
	}

	return false
}

// =============================================================================
// Header Validation
// =============================================================================

func (s *Sentinel) validateHeaders(req *http.Request) bool {
	for i, h := range s.config.Headers {
		value := req.Header.Get(h.Name)

		// Check if required
		if value == "" {
			if h.Required {
				s.log("header %s required but missing", h.Name)
				return false
			}
			continue
		}

		// Regex check
		if s.headerRegex[i] != nil {
			if !s.headerRegex[i].MatchString(value) {
				s.log("header %s failed regex", h.Name)
				return false
			}
			continue
		}

		// Value matching
		if len(h.Values) > 0 {
			matched := false
			matchCount := 0

			for _, v := range h.Values {
				var isMatch bool
				if h.Contains {
					isMatch = strings.Contains(value, v)
				} else {
					isMatch = value == v
				}
				if isMatch {
					matched = true
					matchCount++
				}
			}

			switch h.MatchType {
			case "all":
				if matchCount != len(h.Values) {
					s.log("header %s failed all match", h.Name)
					return false
				}
			case "none":
				if matched {
					s.log("header %s matched blacklist", h.Name)
					return false
				}
			default: // "one" or empty
				if !matched {
					s.log("header %s no match", h.Name)
					return false
				}
			}
		}
	}
	return true
}

// =============================================================================
// Block Request
// =============================================================================

func (s *Sentinel) blockRequest(rw http.ResponseWriter, req *http.Request, reason BlockReason) {
	mode := s.config.ErrorMode
	if mode == "" {
		mode = "403"
	}

	// Silent drop
	if mode == "silent" {
		s.dropConnection(rw, req)
		return
	}

	// Error page
	resp, ok := errorResponses[mode]
	if !ok {
		resp = errorResponses["403"]
	}

	// Try to use custom template for this block reason
	html := getTemplate(reason)
	if html == "" {
		// Fallback to generic template
		html = errorPageTemplate
		html = strings.Replace(html, "{TITLE}", resp.title, -1)
		html = strings.Replace(html, "{MESSAGE}", resp.message, -1)
	}
	// Replace status code placeholder in all templates
	html = strings.Replace(html, "{CODE}", fmt.Sprintf("%d", resp.code), -1)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Connection", "close")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(resp.code)
	rw.Write([]byte(html))
}

func (s *Sentinel) dropConnection(rw http.ResponseWriter, req *http.Request) {
	hj, ok := rw.(http.Hijacker)
	if ok {
		conn, _, err := hj.Hijack()
		if err == nil && conn != nil {
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetLinger(0)
			}
			conn.Close()
			return
		}
	}

	// Fallback
	rw.Header().Set("Connection", "close")
	rw.Header().Set("Content-Length", "0")
	rw.WriteHeader(444)
}

// =============================================================================
// Time-Based Access
// =============================================================================

// parseTimeRange parses "HH:MM-HH:MM" format into timeRange
func parseTimeRange(s string) *timeRange {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return nil
	}

	start := strings.TrimSpace(parts[0])
	end := strings.TrimSpace(parts[1])

	startParts := strings.Split(start, ":")
	endParts := strings.Split(end, ":")

	if len(startParts) != 2 || len(endParts) != 2 {
		return nil
	}

	var tr timeRange
	fmt.Sscanf(startParts[0], "%d", &tr.startHour)
	fmt.Sscanf(startParts[1], "%d", &tr.startMinute)
	fmt.Sscanf(endParts[0], "%d", &tr.endHour)
	fmt.Sscanf(endParts[1], "%d", &tr.endMinute)

	return &tr
}

// isInTimeRange checks if current time is within the range
func (tr *timeRange) contains(hour, minute int) bool {
	if tr == nil {
		return false
	}

	current := hour*60 + minute
	start := tr.startHour*60 + tr.startMinute
	end := tr.endHour*60 + tr.endMinute

	// Handle overnight ranges (e.g., 22:00-06:00)
	if start > end {
		return current >= start || current < end
	}
	return current >= start && current < end
}

// checkTimeAccess verifies if current time allows access
func (s *Sentinel) checkTimeAccess() bool {
	if s.timeLocation == nil {
		return true
	}

	now := time.Now().In(s.timeLocation)
	hour := now.Hour()
	minute := now.Minute()
	weekday := strings.ToLower(now.Weekday().String()[:3]) // mon, tue, etc.

	// Check if today is in allowed days
	if len(s.config.TimeAccess.Days) > 0 {
		dayAllowed := false
		for _, d := range s.config.TimeAccess.Days {
			if strings.ToLower(d) == weekday {
				dayAllowed = true
				break
			}
		}
		if !dayAllowed {
			s.log("day %s not in allowed days", weekday)
			return false
		}
	}

	// Deny range takes precedence
	if s.timeDeny != nil && s.timeDeny.contains(hour, minute) {
		s.log("time %02d:%02d in deny range", hour, minute)
		return false
	}

	// Check allow range (if specified, must be within it)
	if s.timeAllow != nil {
		if !s.timeAllow.contains(hour, minute) {
			s.log("time %02d:%02d not in allow range", hour, minute)
			return false
		}
	}

	return true
}
