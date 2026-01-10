package traefik

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// Sentinel middleware names - used throughout the codebase
const (
	MiddlewareSentinelVPN       = "sentinel_vpn"
	MiddlewareSentinelVPNSilent = "sentinel_vpn_silent"
	MiddlewareSentinelDrop      = "sentinel_drop"
	// With @file suffix for router middleware lists
	MiddlewareSentinelVPNFile       = "sentinel_vpn@file"
	MiddlewareSentinelVPNSilentFile = "sentinel_vpn_silent@file"
)

// Service handles Traefik operations
type Service struct {
	traefikAPI    string
	configPath    string
	staticPath    string
	accessLogPath string
}

var instance *Service

// New creates a new Traefik service
func New() *Service {
	configDir := helper.GetEnv("TRAEFIK_CONFIG")
	configPath := configDir + "/core.yml"

	instance = &Service{
		traefikAPI:    helper.GetEnv("TRAEFIK_API"),
		configPath:    configPath,
		staticPath:    helper.GetEnv("TRAEFIK_STATIC"),
		accessLogPath: helper.GetEnv("TRAEFIK_LOGS"),
	}
	return instance
}

// GetService returns the singleton instance
func GetService() *Service {
	return instance
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetOverview":  s.handleOverview,
		"GetConfig":    s.handleGetConfig,
		"UpdateConfig": s.handleUpdateConfig,
		"GetVPNOnly":   s.handleGetVPNOnly,
		"SetVPNOnly":   s.handleSetVPNOnly,
	}
}

func (s *Service) fetchTraefikAPI(path string) (map[string]interface{}, error) {
	resp, err := http.Get(s.traefikAPI + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) fetchTraefikAPIArray(path string) ([]interface{}, error) {
	resp, err := http.Get(s.traefikAPI + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// handleOverview fetches overview, routers, services, and middlewares in parallel
func (s *Service) handleOverview(w http.ResponseWriter, r *http.Request) {
	type result struct {
		data interface{}
		err  error
	}

	// Fetch all endpoints in parallel
	overviewCh := make(chan result, 1)
	routersCh := make(chan result, 1)
	servicesCh := make(chan result, 1)
	middlewaresCh := make(chan result, 1)

	go func() {
		data, err := s.fetchTraefikAPI("/overview")
		overviewCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchTraefikAPIArray("/http/routers")
		routersCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchTraefikAPIArray("/http/services")
		servicesCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchTraefikAPIArray("/http/middlewares")
		middlewaresCh <- result{data, err}
	}()

	// Collect results
	overview := <-overviewCh
	routers := <-routersCh
	services := <-servicesCh
	middlewares := <-middlewaresCh

	// Check for errors on overview (required)
	if overview.err != nil {
		router.JSONError(w, overview.err.Error(), http.StatusBadGateway)
		return
	}

	// Build combined response (use empty arrays for failed fetches)
	response := map[string]interface{}{
		"overview": overview.data,
	}

	if routers.err == nil {
		response["routers"] = routers.data
	} else {
		response["routers"] = []interface{}{}
	}

	if services.err == nil {
		response["services"] = services.data
	} else {
		response["services"] = []interface{}{}
	}

	if middlewares.err == nil {
		response["middlewares"] = middlewares.data
	} else {
		response["middlewares"] = []interface{}{}
	}

	router.JSON(w, response)
}

// TraefikConfig holds traefik configuration
type TraefikConfig struct {
	RateLimitAverage  int      `json:"rateLimitAverage"`
	RateLimitBurst    int      `json:"rateLimitBurst"`
	StrictRateAverage int      `json:"strictRateAverage"`
	StrictRateBurst   int      `json:"strictRateBurst"`
	SecurityHeaders   bool     `json:"securityHeaders"`
	IPAllowlist       []string `json:"ipAllowlist"`
	IPAllowEnabled    bool     `json:"ipAllowEnabled"`
	DashboardEnabled  bool     `json:"dashboardEnabled"`
}

// GetConfig returns current traefik configuration
func (s *Service) GetConfig() *TraefikConfig {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil
	}

	content := string(data)

	// Fetch middlewares once and extract all rate limit values
	middlewares, _ := helper.GetYAMLPath(content, "http.middlewares")
	mwMap, _ := middlewares.(map[string]interface{})
	if mwMap == nil {
		mwMap = make(map[string]interface{})
	}

	config := &TraefikConfig{
		RateLimitAverage:  getNestedInt(mwMap, []string{"rate-limit", "rateLimit", "average"}, 100),
		RateLimitBurst:    getNestedInt(mwMap, []string{"rate-limit", "rateLimit", "burst"}, 200),
		StrictRateAverage: getNestedInt(mwMap, []string{"rate-limit-strict", "rateLimit", "average"}, 10),
		StrictRateBurst:   getNestedInt(mwMap, []string{"rate-limit-strict", "rateLimit", "burst"}, 20),
		SecurityHeaders:   mwMap["security-headers"] != nil,
		IPAllowlist:       extractIPList(content),
		IPAllowEnabled:    mwMap[MiddlewareSentinelVPN] != nil,
		DashboardEnabled:  true,
	}

	if s.staticPath != "" {
		if staticData, err := os.ReadFile(s.staticPath); err == nil {
			staticContent := string(staticData)
			if val, err := helper.GetYAMLPath(staticContent, "api.dashboard"); err == nil {
				if b, ok := val.(bool); ok {
					config.DashboardEnabled = b
				}
			}
		}
	}

	return config
}

func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := s.GetConfig()
	if config == nil {
		router.JSONError(w, "Failed to read config", http.StatusInternalServerError)
		return
	}
	router.JSON(w, config)
}

func (s *Service) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var config struct {
		RateLimitAverage int      `json:"rateLimitAverage"`
		RateLimitBurst   int      `json:"rateLimitBurst"`
		StrictRateAvg    int      `json:"strictRateAverage"`
		StrictRateBurst  int      `json:"strictRateBurst"`
		SecurityHeaders  bool     `json:"securityHeaders"`
		IPAllowlist      []string `json:"ipAllowlist"`
		IPAllowEnabled   bool     `json:"ipAllowEnabled"`
		DashboardEnabled *bool    `json:"dashboardEnabled,omitempty"`
	}
	if !router.DecodeJSONOrError(w, r, &config) {
		return
	}

	// Validate IP allowlist entries
	if err := helper.ValidateIPList(config.IPAllowlist); err != nil {
		router.JSONError(w, "Invalid IP allowlist: "+err.Error(), http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(s.configPath)
	if err != nil {
		router.JSONError(w, "Failed to read config", http.StatusInternalServerError)
		return
	}

	content := string(data)

	// Update all values using proper YAML parsing
	content, err = helper.UpdateYAMLPaths(content, []helper.YAMLUpdate{
		{Path: "http.middlewares.rate-limit.rateLimit.average", Value: config.RateLimitAverage},
		{Path: "http.middlewares.rate-limit.rateLimit.burst", Value: config.RateLimitBurst},
		{Path: "http.middlewares.rate-limit-strict.rateLimit.average", Value: config.StrictRateAvg},
		{Path: "http.middlewares.rate-limit-strict.rateLimit.burst", Value: config.StrictRateBurst},
		{Path: "http.middlewares.sentinel_vpn.plugin.sentinel.ipFilter.sourceRange", ListValue: config.IPAllowlist},
		{Path: "http.middlewares.sentinel_vpn_silent.plugin.sentinel.ipFilter.sourceRange", ListValue: config.IPAllowlist},
	})
	if err != nil {
		log.Printf("Warning: some YAML updates failed: %v", err)
	}

	if err := os.WriteFile(s.configPath, []byte(content), 0644); err != nil {
		router.JSONError(w, "Failed to write config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update static config for dashboard if provided
	restartRequired := false
	if config.DashboardEnabled != nil && s.staticPath != "" {
		if staticData, err := os.ReadFile(s.staticPath); err == nil {
			staticContent := string(staticData)

			// Determine dashboard address based on enabled state
			port := os.Getenv("TRAEFIK_PORT")
			containerIP := os.Getenv("TRAEFIK_CONTAINER_IP")
			if containerIP == "" {
				containerIP = "172.18.0.2" // fallback
			}

			var address string
			if *config.DashboardEnabled {
				address = ":" + port // public
			} else {
				address = containerIP + ":" + port // internal only
			}

			// Update dashboard enabled and address using proper YAML parsing
			newStaticContent, err := helper.UpdateYAMLPaths(staticContent, []helper.YAMLUpdate{
				{Path: "api.dashboard", Value: *config.DashboardEnabled},
				{Path: "entryPoints.traefik.address", Value: address},
			})
			if err != nil {
				log.Printf("Warning: some static config updates failed: %v", err)
			}

			if newStaticContent != staticContent {
				if err := os.WriteFile(s.staticPath, []byte(newStaticContent), 0644); err != nil {
					log.Printf("Failed to update static config: %v", err)
				} else {
					restartRequired = true
				}
			}
		}
	}

	log.Printf("Traefik config updated")
	router.JSON(w, map[string]interface{}{
		"status":          "updated",
		"restartRequired": restartRequired,
	})
}

// getNestedInt extracts an int from a nested map path, returns defaultVal if not found
func getNestedInt(data map[string]interface{}, keys []string, defaultVal int) int {
	current := data
	for i, key := range keys {
		val, ok := current[key]
		if !ok {
			return defaultVal
		}
		if i == len(keys)-1 {
			// Last key - expect int
			switch v := val.(type) {
			case int:
				return v
			case int64:
				return int(v)
			case float64:
				return int(v)
			default:
				return defaultVal
			}
		}
		// Navigate deeper
		current, ok = val.(map[string]interface{})
		if !ok {
			return defaultVal
		}
	}
	return defaultVal
}

func extractIPList(content string) []string {
	path := "http.middlewares." + MiddlewareSentinelVPN + ".plugin.sentinel.ipFilter.sourceRange"
	val, err := helper.GetYAMLPath(content, path)
	if err != nil {
		return nil
	}

	// Convert to string slice
	list, ok := val.([]interface{})
	if !ok {
		return nil
	}

	var ips []string
	for _, item := range list {
		if s, ok := item.(string); ok {
			ips = append(ips, s)
		}
	}
	return ips
}

// middlewareExists checks if a middleware is defined in the config
func middlewareExists(content, middlewareName string) bool {
	path := "http.middlewares." + middlewareName
	_, err := helper.GetYAMLPath(content, path)
	return err == nil
}

// routerHasMiddleware checks if a router has a specific middleware
func routerHasMiddleware(content, routerName, middlewareName string) bool {
	path := "http.routers." + routerName + ".middlewares"
	has, err := helper.ArrayContainsYAMLItem(content, path, middlewareName)
	return err == nil && has
}

// addMiddlewareToRouter adds a middleware to a router's middleware list
func (s *Service) addMiddlewareToRouter(routerName, middlewareName string) error {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	content := string(data)

	// Check if middleware exists
	if !middlewareExists(content, middlewareName) {
		return fmt.Errorf("middleware '%s' does not exist", middlewareName)
	}

	// Check if router exists
	routerPath := "http.routers." + routerName
	if _, err := helper.GetYAMLPath(content, routerPath); err != nil {
		return fmt.Errorf("router '%s' not found", routerName)
	}

	// Insert middleware into router's middlewares array
	path := "http.routers." + routerName + ".middlewares"
	newContent, err := helper.InsertYAMLArrayItem(content, path, middlewareName)
	if err != nil {
		return fmt.Errorf("failed to add middleware: %w", err)
	}

	if newContent == content {
		return nil // Already has it, no change
	}

	if err := os.WriteFile(s.configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	log.Printf("Added middleware '%s' to router '%s'", middlewareName, routerName)
	return nil
}

// removeMiddlewareFromRouter removes a middleware from a router's middleware list
func (s *Service) removeMiddlewareFromRouter(routerName, middlewareName string) error {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	content := string(data)

	// Remove middleware from router's middlewares array
	path := "http.routers." + routerName + ".middlewares"
	newContent, err := helper.RemoveYAMLArrayItem(content, path, middlewareName)
	if err != nil {
		// Path might not exist (no middlewares), that's fine
		return nil
	}

	if newContent == content {
		return nil // Wasn't there, no change
	}

	if err := os.WriteFile(s.configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	log.Printf("Removed middleware '%s' from router '%s'", middlewareName, routerName)
	return nil
}

// GetVPNOnlyMode returns the current VPN-only mode ("off", "403", or "silent")
func (s *Service) GetVPNOnlyMode() string {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return "off"
	}

	content := string(data)
	if routerHasMiddleware(content, "ui", MiddlewareSentinelVPNSilent) {
		return "silent"
	} else if routerHasMiddleware(content, "ui", MiddlewareSentinelVPN) {
		return "403"
	}
	return "off"
}

// handleGetVPNOnly returns VPN-only mode status for the UI
func (s *Service) handleGetVPNOnly(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"mode": s.GetVPNOnlyMode()})
}

// handleSetVPNOnly sets VPN-only mode for the UI
// mode: "off", "403", or "silent"
func (s *Service) handleSetVPNOnly(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate mode
	if req.Mode != "off" && req.Mode != "403" && req.Mode != "silent" {
		router.JSONError(w, "invalid mode: must be 'off', '403', or 'silent'", http.StatusBadRequest)
		return
	}

	// Routers to update (HTTP and HTTPS)
	routers := []string{"ui", "ui-secure"}

	// Remove both middlewares from all routers first
	for _, rtr := range routers {
		s.removeMiddlewareFromRouter(rtr, MiddlewareSentinelVPN)
		s.removeMiddlewareFromRouter(rtr, MiddlewareSentinelVPNSilent)
	}

	// Add the appropriate middleware to all routers
	var err error
	for _, routerName := range routers {
		switch req.Mode {
		case "403":
			err = s.addMiddlewareToRouter(routerName, MiddlewareSentinelVPN)
		case "silent":
			err = s.addMiddlewareToRouter(routerName, MiddlewareSentinelVPNSilent)
		}
		if err != nil {
			// Log but continue - router may not exist (e.g., SSL not enabled)
			log.Printf("Warning: could not update router %s: %v", routerName, err)
			err = nil // Reset error so we continue
		}
	}

	router.JSON(w, map[string]string{"mode": req.Mode})
}

// escapeYAMLString escapes a string for safe YAML output
func escapeYAMLString(s string) string {
	// Replace backslashes first, then other special chars
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// SentinelConfig represents per-domain sentinel middleware configuration
type SentinelConfig struct {
	Enabled   bool   `json:"enabled"`
	ErrorMode string `json:"errorMode,omitempty"` // "403", "404", "503", "silent"
	IPFilter  struct {
		SourceRange []string `json:"sourceRange,omitempty"`
	} `json:"ipFilter,omitempty"`
	Maintenance *struct {
		Enabled bool   `json:"enabled"`
		Message string `json:"message,omitempty"`
	} `json:"maintenance,omitempty"`
	TimeAccess *struct {
		Enabled    bool     `json:"enabled,omitempty"`
		Timezone   string   `json:"timezone,omitempty"`
		Days       []string `json:"days,omitempty"`       // mon, tue, wed, thu, fri, sat, sun
		AllowRange string   `json:"allowRange,omitempty"` // "HH:MM-HH:MM"
		DenyRange  string   `json:"denyRange,omitempty"`  // "HH:MM-HH:MM"
	} `json:"timeAccess,omitempty"`
	Headers []struct {
		Name      string   `json:"name"`
		Values    []string `json:"values,omitempty"`
		MatchType string   `json:"matchType,omitempty"` // "one", "all", "none"
		Regex     string   `json:"regex,omitempty"`
		Required  bool     `json:"required,omitempty"`
		Contains  bool     `json:"contains,omitempty"`
	} `json:"headers,omitempty"`
	UserAgents *struct {
		Enabled bool     `json:"enabled,omitempty"`
		Block   []string `json:"block,omitempty"`
		Allow   []string `json:"allow,omitempty"`
	} `json:"userAgents,omitempty"`
}

// DomainRouteConfig represents a domain route for Traefik config generation
type DomainRouteConfig struct {
	Domain         string
	TargetIP       string
	TargetPort     int
	HTTPSBackend   bool
	Middlewares    []string
	AccessMode     string          // "vpn" or "public"
	FrontendSSL    bool            // use websecure entrypoint with TLS
	SentinelConfig *SentinelConfig // per-domain sentinel middleware config
}

// GenerateDomainRoutes writes domain routes to Traefik's dynamic config directory
func GenerateDomainRoutes(configDir string, routes []DomainRouteConfig) error {
	var sb strings.Builder

	sb.WriteString("# Domain Routes - Auto-generated, do not edit manually\n")
	sb.WriteString("# Generated at: " + time.Now().Format(time.RFC3339) + "\n\n")

	if len(routes) == 0 {
		sb.WriteString("# No routes configured\n")
	} else {
		sb.WriteString("http:\n")
		sb.WriteString("  routers:\n")

		// Track routes that need per-domain middlewares
		var sentinelMiddlewares []struct {
			name   string
			config *SentinelConfig
		}

		for _, route := range routes {
			name := helper.SanitizeDomainName(route.Domain)

			// Build middlewares list
			middlewares := make([]string, len(route.Middlewares))
			copy(middlewares, route.Middlewares)

			// Add per-domain sentinel config middleware if configured and enabled
			if route.SentinelConfig != nil && route.SentinelConfig.Enabled {
				mwName := fmt.Sprintf("sentinel_domain-%s", name)
				middlewares = append([]string{mwName}, middlewares...) // prepend
				sentinelMiddlewares = append(sentinelMiddlewares, struct {
					name   string
					config *SentinelConfig
				}{mwName, route.SentinelConfig})
			}

			// HTTP router (web entrypoint) - always created
			sb.WriteString(fmt.Sprintf("    domain-%s:\n", name))
			sb.WriteString(fmt.Sprintf("      rule: \"Host(`%s`)\"\n", route.Domain))
			sb.WriteString(fmt.Sprintf("      service: domain-%s-svc\n", name))
			sb.WriteString("      priority: 50\n")
			sb.WriteString("      entryPoints:\n")
			sb.WriteString("        - web\n")
			if len(middlewares) > 0 {
				sb.WriteString("      middlewares:\n")
				for _, mw := range middlewares {
					sb.WriteString(fmt.Sprintf("        - %s\n", mw))
				}
			}
			sb.WriteString("\n")

			// HTTPS router (websecure entrypoint) - only if FrontendSSL is enabled
			if route.FrontendSSL {
				sb.WriteString(fmt.Sprintf("    domain-%s-secure:\n", name))
				sb.WriteString(fmt.Sprintf("      rule: \"Host(`%s`)\"\n", route.Domain))
				sb.WriteString(fmt.Sprintf("      service: domain-%s-svc\n", name))
				sb.WriteString("      priority: 50\n")
				sb.WriteString("      entryPoints:\n")
				sb.WriteString("        - websecure\n")
				if len(middlewares) > 0 {
					sb.WriteString("      middlewares:\n")
					for _, mw := range middlewares {
						sb.WriteString(fmt.Sprintf("        - %s\n", mw))
					}
				}
				// TLS configuration based on access mode
				if route.AccessMode == "public" {
					// Public mode: use Let's Encrypt
					sb.WriteString("      tls:\n")
					sb.WriteString("        certResolver: letsencrypt\n")
					sb.WriteString("        domains:\n")
					sb.WriteString(fmt.Sprintf("          - main: \"%s\"\n", route.Domain))
				} else {
					// VPN mode: use default/self-signed cert
					sb.WriteString("      tls: {}\n")
				}
				sb.WriteString("\n")
			}
		}

		sb.WriteString("  services:\n")
		for _, route := range routes {
			name := helper.SanitizeDomainName(route.Domain)
			protocol := "http"
			if route.HTTPSBackend {
				protocol = "https"
			}
			sb.WriteString(fmt.Sprintf("    domain-%s-svc:\n", name))
			sb.WriteString("      loadBalancer:\n")
			sb.WriteString("        servers:\n")
			sb.WriteString(fmt.Sprintf("          - url: \"%s://%s:%d\"\n", protocol, route.TargetIP, route.TargetPort))
			sb.WriteString("\n")
		}

		// Generate per-domain sentinel middlewares
		if len(sentinelMiddlewares) > 0 {
			sb.WriteString("  middlewares:\n")
			for _, mw := range sentinelMiddlewares {
				sb.WriteString(fmt.Sprintf("    %s:\n", mw.name))
				sb.WriteString("      plugin:\n")
				sb.WriteString("        sentinel:\n")

				// IP Filter
				if len(mw.config.IPFilter.SourceRange) > 0 {
					sb.WriteString("          ipFilter:\n")
					sb.WriteString("            sourceRange:\n")
					for _, ip := range mw.config.IPFilter.SourceRange {
						sb.WriteString(fmt.Sprintf("              - \"%s\"\n", escapeYAMLString(ip)))
					}
				}

				// Error Mode (whitelist valid values)
				errorMode := mw.config.ErrorMode
				switch errorMode {
				case "403", "404", "503", "silent":
					// valid
				default:
					errorMode = "403"
				}
				sb.WriteString(fmt.Sprintf("          errorMode: \"%s\"\n", errorMode))

				// Maintenance Mode
				if mw.config.Maintenance != nil && mw.config.Maintenance.Enabled {
					sb.WriteString("          maintenance:\n")
					sb.WriteString("            enabled: true\n")
					if mw.config.Maintenance.Message != "" {
						sb.WriteString(fmt.Sprintf("            message: \"%s\"\n", escapeYAMLString(mw.config.Maintenance.Message)))
					}
				}

				// Time Access
				if mw.config.TimeAccess != nil && (len(mw.config.TimeAccess.Days) > 0 || mw.config.TimeAccess.AllowRange != "" || mw.config.TimeAccess.DenyRange != "") {
					sb.WriteString("          timeAccess:\n")
					sb.WriteString("            enabled: true\n")
					if mw.config.TimeAccess.Timezone != "" {
						sb.WriteString(fmt.Sprintf("            timezone: \"%s\"\n", escapeYAMLString(mw.config.TimeAccess.Timezone)))
					}
					if len(mw.config.TimeAccess.Days) > 0 {
						sb.WriteString("            days:\n")
						for _, day := range mw.config.TimeAccess.Days {
							sb.WriteString(fmt.Sprintf("              - \"%s\"\n", escapeYAMLString(day)))
						}
					}
					if mw.config.TimeAccess.AllowRange != "" {
						sb.WriteString(fmt.Sprintf("            allowRange: \"%s\"\n", escapeYAMLString(mw.config.TimeAccess.AllowRange)))
					}
					if mw.config.TimeAccess.DenyRange != "" {
						sb.WriteString(fmt.Sprintf("            denyRange: \"%s\"\n", escapeYAMLString(mw.config.TimeAccess.DenyRange)))
					}
				}

				// Headers
				if len(mw.config.Headers) > 0 {
					sb.WriteString("          headers:\n")
					for _, h := range mw.config.Headers {
						sb.WriteString(fmt.Sprintf("            - name: \"%s\"\n", escapeYAMLString(h.Name)))
						if len(h.Values) > 0 {
							sb.WriteString("              values:\n")
							for _, v := range h.Values {
								sb.WriteString(fmt.Sprintf("                - \"%s\"\n", escapeYAMLString(v)))
							}
						}
						if h.MatchType != "" {
							matchType := h.MatchType
							switch matchType {
							case "one", "all", "none":
								// valid
							default:
								matchType = "one"
							}
							sb.WriteString(fmt.Sprintf("              matchType: \"%s\"\n", matchType))
						}
						if h.Regex != "" {
							sb.WriteString(fmt.Sprintf("              regex: \"%s\"\n", escapeYAMLString(h.Regex)))
						}
						if h.Required {
							sb.WriteString("              required: true\n")
						}
						if h.Contains {
							sb.WriteString("              contains: true\n")
						}
					}
				}

				// User Agents
				if mw.config.UserAgents != nil && (len(mw.config.UserAgents.Block) > 0 || len(mw.config.UserAgents.Allow) > 0) {
					sb.WriteString("          userAgents:\n")
					sb.WriteString("            enabled: true\n")
					if len(mw.config.UserAgents.Block) > 0 {
						sb.WriteString("            block:\n")
						for _, ua := range mw.config.UserAgents.Block {
							sb.WriteString(fmt.Sprintf("              - \"%s\"\n", escapeYAMLString(ua)))
						}
					}
					if len(mw.config.UserAgents.Allow) > 0 {
						sb.WriteString("            allow:\n")
						for _, ua := range mw.config.UserAgents.Allow {
							sb.WriteString(fmt.Sprintf("              - \"%s\"\n", escapeYAMLString(ua)))
						}
					}
				}

				sb.WriteString("\n")
			}
		}
	}

	// Write to domains.yml
	configPath := configDir + "/domains.yml"
	if err := os.WriteFile(configPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	log.Printf("Generated Traefik domain routes config with %d routes", len(routes))
	return nil
}

// CertificateInfo holds certificate data parsed from acme.json
type CertificateInfo struct {
	Domain    string    `json:"domain"`
	NotBefore time.Time `json:"notBefore,omitempty"`
	NotAfter  time.Time `json:"notAfter,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Status    string    `json:"status"` // "valid", "warning", "critical", "expired", "pending", "error"
	DaysLeft  int       `json:"daysLeft,omitempty"`
	Error     string    `json:"error,omitempty"` // error message if status is "error"
}

// acmeStorage represents the structure of acme.json
type acmeStorage struct {
	Letsencrypt struct {
		Account struct {
			Email string `json:"Email"`
		} `json:"Account"`
		Certificates []struct {
			Domain struct {
				Main string   `json:"main"`
				SANs []string `json:"sans"`
			} `json:"domain"`
			Certificate string `json:"certificate"`
			Key         string `json:"key"`
		} `json:"Certificates"`
	} `json:"letsencrypt"`
}

// GetCertificates parses acme.json and returns certificate info
func GetCertificates() ([]CertificateInfo, error) {
	acmePath := helper.GetEnvOptional("TRAEFIK_ACME", "/traefik/acme.json")

	data, err := os.ReadFile(acmePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []CertificateInfo{}, nil // No certificates yet
		}
		return nil, fmt.Errorf("failed to read acme.json: %v", err)
	}

	if len(data) == 0 {
		return []CertificateInfo{}, nil
	}

	var storage acmeStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return nil, fmt.Errorf("failed to parse acme.json: %v", err)
	}

	certs := []CertificateInfo{}
	now := time.Now()

	for _, cert := range storage.Letsencrypt.Certificates {
		// Decode certificate to get expiration
		certPEM, err := base64.StdEncoding.DecodeString(cert.Certificate)
		if err != nil {
			log.Printf("Warning: failed to decode certificate for %s: %v", cert.Domain.Main, err)
			continue
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			log.Printf("Warning: failed to decode PEM block for %s", cert.Domain.Main)
			continue
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Warning: failed to parse certificate for %s: %v", cert.Domain.Main, err)
			continue
		}

		daysLeft := int(x509Cert.NotAfter.Sub(now).Hours() / 24)
		status := "valid"
		if daysLeft <= 0 {
			status = "expired"
		} else if daysLeft <= 7 {
			status = "critical"
		} else if daysLeft <= 30 {
			status = "warning"
		}

		certs = append(certs, CertificateInfo{
			Domain:    cert.Domain.Main,
			NotBefore: x509Cert.NotBefore,
			NotAfter:  x509Cert.NotAfter,
			Issuer:    x509Cert.Issuer.CommonName,
			Status:    status,
			DaysLeft:  daysLeft,
		})
	}

	return certs, nil
}

// GetACMEError checks traefik.log for ACME errors for a specific domain
func GetACMEError(domain string) string {
	logPath := helper.GetEnv("TRAEFIK_MAIN_LOG")

	data, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	// Start from end, look for recent errors
	startIdx := len(lines) - 500
	if startIdx < 0 {
		startIdx = 0
	}

	domainLower := strings.ToLower(domain)
	for i := len(lines) - 1; i >= startIdx; i-- {
		line := lines[i]
		lineLower := strings.ToLower(line)

		// Check if line contains domain and is an ACME/certificate error
		if strings.Contains(lineLower, domainLower) &&
			(strings.Contains(lineLower, "unable to obtain") ||
				(strings.Contains(lineLower, "acme") && strings.Contains(lineLower, "error"))) {

			// Try to extract meaningful error message
			// Format 1: msg="..." (key=value format)
			if idx := strings.Index(line, "msg="); idx != -1 {
				msg := line[idx+4:]
				if strings.HasPrefix(msg, "\"") {
					msg = msg[1:]
					if endIdx := strings.Index(msg, "\""); endIdx != -1 {
						msg = msg[:endIdx]
					}
				}
				if len(msg) > 200 {
					msg = msg[:200] + "..."
				}
				return msg
			}

			// Format 2: "msg":"..." (JSON format)
			if idx := strings.Index(line, "\"msg\":\""); idx != -1 {
				msg := line[idx+7:]
				if endIdx := strings.Index(msg, "\""); endIdx != -1 {
					msg = msg[:endIdx]
				}
				if len(msg) > 200 {
					msg = msg[:200] + "..."
				}
				return msg
			}

			// Format 3: error="..."
			if idx := strings.Index(line, "error=\""); idx != -1 {
				msg := line[idx+7:]
				if endIdx := strings.Index(msg, "\""); endIdx != -1 {
					msg = msg[:endIdx]
				}
				if len(msg) > 200 {
					msg = msg[:200] + "..."
				}
				return msg
			}

			// Fallback: check for rate limit
			if strings.Contains(lineLower, "ratelimited") || strings.Contains(lineLower, "rate limit") {
				return "Rate limited by Let's Encrypt"
			}

			return "Certificate generation failed"
		}
	}
	return ""
}

// GetPendingSSLDomains returns domains that have SSL enabled but no certificate yet
func GetPendingSSLDomains() ([]CertificateInfo, error) {
	// Get existing certificates
	existingCerts, err := GetCertificates()
	if err != nil {
		return nil, err
	}

	// Create map of domains that have certs
	certMap := make(map[string]bool)
	for _, c := range existingCerts {
		certMap[c.Domain] = true
	}

	// Read domains.yml to find domains with frontendSsl=true
	dynamicPath := helper.GetEnvOptional("TRAEFIK_DYNAMIC", "/traefik/dynamic")
	domainsFile := filepath.Join(dynamicPath, "domains.yml")

	data, err := os.ReadFile(domainsFile)
	if err != nil {
		return []CertificateInfo{}, nil // No domains file yet
	}

	// Parse YAML to find domains with SSL enabled
	var pending []CertificateInfo
	lines := strings.Split(string(data), "\n")
	var currentDomain string
	var hasCertResolver bool

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Look for router definitions like "domain-wiki-example-com-secure:"
		if strings.HasSuffix(trimmed, "-secure:") && strings.HasPrefix(trimmed, "domain-") {
			currentDomain = ""
			hasCertResolver = false
		}

		// Look for Host rule to extract domain
		if strings.Contains(trimmed, "Host(`") && currentDomain == "" {
			start := strings.Index(trimmed, "Host(`") + 6
			end := strings.Index(trimmed[start:], "`")
			if end > 0 {
				currentDomain = trimmed[start : start+end]
			}
		}

		// Check if this router uses certResolver
		if strings.Contains(trimmed, "certResolver:") {
			hasCertResolver = true
		}

		// At end of router block, check if it's pending
		if currentDomain != "" && hasCertResolver {
			if !certMap[currentDomain] {
				// No cert exists - check for error
				acmeError := GetACMEError(currentDomain)
				status := "pending"
				if acmeError != "" {
					status = "error"
				}
				pending = append(pending, CertificateInfo{
					Domain: currentDomain,
					Status: status,
					Error:  acmeError,
				})
				certMap[currentDomain] = true // Avoid duplicates
			}
			currentDomain = ""
			hasCertResolver = false
		}
	}

	return pending, nil
}
