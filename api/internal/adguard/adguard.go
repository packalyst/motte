package adguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// enabledWord renders a bool as an activity-feed verb.
func enabledWord(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// CredentialsProvider is a callback to get AdGuard credentials without importing settings
var CredentialsProvider func() (username, password string)

// httpClient with timeout for AdGuard API requests
var httpClient = &http.Client{Timeout: helper.HTTPClientTimeout}

// Service handles AdGuard operations
type Service struct {
	adguardAPI string
}

// Global instance for package-level helper functions
var serviceInstance *Service

// GetService returns the global service instance
func GetService() *Service {
	return serviceInstance
}

// New creates a new AdGuard service
func New() *Service {
	port := os.Getenv("ADGUARD_PORT")
	if port == "" {
		port = "8083"
	}
	svc := &Service{
		adguardAPI: "http://127.0.0.1:" + port,
	}

	serviceInstance = svc
	log.Printf("AdGuard service initialized, API: %s", svc.adguardAPI)
	return svc
}

// getCredentials fetches credentials via provider callback, falls back to env vars
func (s *Service) getCredentials() (username, password string) {
	// Try provider callback first (set by main.go to get from settings)
	if CredentialsProvider != nil {
		username, password = CredentialsProvider()
	}

	// Fallback to env vars if not from provider
	if username == "" {
		username = os.Getenv("ADGUARD_USER")
	}
	if password == "" {
		password = os.Getenv("ADGUARD_PASS")
	}

	return username, password
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetOverview":     s.handleOverview,
		"UpdateConfig":    s.handleConfig,
		"GetFiltering":    s.handleGetFiltering,
		"UpdateFiltering": s.handleFilteringAction,
		"GetRewrites":     s.handleGetRewrites,
		"UpdateRewrites":  s.handleRewriteAction,
	}
}

func (s *Service) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, s.adguardAPI+path, body)
	if err != nil {
		return nil, err
	}

	// Only set Content-Type if there's a body
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	username, password := s.getCredentials()
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	return httpClient.Do(req)
}

func (s *Service) proxyGet(w http.ResponseWriter, path string) {
	resp, err := s.doRequest("GET", path, nil)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusFailedDependency)
		return
	}
	defer resp.Body.Close()

	// Check for auth errors - return 424 (Failed Dependency) to avoid Cloudflare interception
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		router.JSONError(w, "AdGuard authentication failed. Check credentials in Settings.", http.StatusFailedDependency)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyError writes error response from upstream if status >= 400, returns true if error occurred
func proxyError(w http.ResponseWriter, resp *http.Response) bool {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		router.JSONError(w, "AdGuard authentication failed. Check credentials in Settings.", http.StatusFailedDependency)
		return true
	}
	if resp.StatusCode >= 400 {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return true
	}
	return false
}

// fetchJSON fetches JSON from AdGuard API and decodes it
func (s *Service) fetchJSON(path string) (interface{}, error) {
	resp, err := s.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for auth errors before decoding
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("AdGuard authentication failed. Check credentials in Settings.")
	}

	// Check for other error status codes
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("AdGuard API error: %s", resp.Status)
	}

	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// handleOverview fetches status, stats, and protection settings in parallel
func (s *Service) handleOverview(w http.ResponseWriter, r *http.Request) {
	type result struct {
		data interface{}
		err  error
	}

	// Fetch all endpoints in parallel
	statusCh := make(chan result, 1)
	statsCh := make(chan result, 1)
	safeBrowsingCh := make(chan result, 1)
	parentalCh := make(chan result, 1)
	safeSearchCh := make(chan result, 1)
	blockedCh := make(chan result, 1)
	availableCh := make(chan result, 1)
	dnsConfigCh := make(chan result, 1)

	go func() {
		data, err := s.fetchJSON("/control/status")
		statusCh <- result{data, err}
	}()
	go func() {
		// AdGuard is asymmetric: config is READ from /control/dns_info (returns disable_ipv6
		// et al.) but WRITTEN to POST /control/dns_config. Reading dns_config gave no
		// disable_ipv6, so the AAAA checkbox never reflected the saved state.
		data, err := s.fetchJSON("/control/dns_info")
		dnsConfigCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/stats")
		statsCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/safebrowsing/status")
		safeBrowsingCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/parental/status")
		parentalCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/safesearch/status")
		safeSearchCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/blocked_services/list")
		blockedCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/blocked_services/all")
		availableCh <- result{data, err}
	}()

	// Collect results
	status := <-statusCh
	stats := <-statsCh
	safeBrowsing := <-safeBrowsingCh
	parental := <-parentalCh
	safeSearch := <-safeSearchCh
	blocked := <-blockedCh
	available := <-availableCh
	dnsConfig := <-dnsConfigCh

	// Check for critical errors (status is required)
	if status.err != nil {
		router.JSONError(w, status.err.Error(), http.StatusFailedDependency)
		return
	}

	// Build combined response
	response := map[string]interface{}{
		"status": status.data,
	}

	if stats.err == nil {
		response["stats"] = stats.data
	}
	if safeBrowsing.err == nil {
		response["safeBrowsing"] = safeBrowsing.data
	}
	if parental.err == nil {
		response["parental"] = parental.data
	}
	if safeSearch.err == nil {
		response["safeSearch"] = safeSearch.data
	}
	if blocked.err == nil {
		response["blockedServices"] = blocked.data
	}
	if available.err == nil {
		response["availableServices"] = available.data
	}
	if dnsConfig.err == nil {
		response["dnsConfig"] = dnsConfig.data // includes disable_ipv6
	}

	router.JSON(w, response)
}

var validConfigTypes = []string{"protection", "blockAAAA", "safeBrowsing", "parental", "safeSearch", "blockedServices"}

// handleConfig handles unified config updates
func (s *Service) handleConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string   `json:"type"`
		Enabled  *bool    `json:"enabled,omitempty"`
		Services []string `json:"services,omitempty"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate type
	if req.Type == "" {
		router.JSON(w, map[string]interface{}{
			"error":      "type field required",
			"validTypes": validConfigTypes,
		})
		return
	}

	switch req.Type {
	case "protection":
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: protection", http.StatusBadRequest)
			return
		}
		body := `{"protection_enabled":` + strconv.FormatBool(*req.Enabled) + `}`
		resp, err := s.doRequest("POST", "/control/dns_config", newStringReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		events.Log("adguard", "config_"+req.Type, events.SeverityInfo,
			fmt.Sprintf("%s %s", req.Type, enabledWord(*req.Enabled)))
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "blockAAAA":
		// Force IPv4-only DNS by making AdGuard drop AAAA (IPv6) answers.
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: blockAAAA", http.StatusBadRequest)
			return
		}
		body := `{"disable_ipv6":` + strconv.FormatBool(*req.Enabled) + `}`
		resp, err := s.doRequest("POST", "/control/dns_config", newStringReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		events.Log("adguard", "config_"+req.Type, events.SeverityInfo,
			fmt.Sprintf("%s %s", req.Type, enabledWord(*req.Enabled)))
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "safeBrowsing":
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: safeBrowsing", http.StatusBadRequest)
			return
		}
		path := "/control/safebrowsing/"
		if *req.Enabled {
			path += "enable"
		} else {
			path += "disable"
		}
		resp, err := s.doRequest("POST", path, nil)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		events.Log("adguard", "config_"+req.Type, events.SeverityInfo,
			fmt.Sprintf("%s %s", req.Type, enabledWord(*req.Enabled)))
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "parental":
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: parental", http.StatusBadRequest)
			return
		}
		path := "/control/parental/"
		if *req.Enabled {
			path += "enable"
		} else {
			path += "disable"
		}
		resp, err := s.doRequest("POST", path, nil)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		events.Log("adguard", "config_"+req.Type, events.SeverityInfo,
			fmt.Sprintf("%s %s", req.Type, enabledWord(*req.Enabled)))
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "safeSearch":
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: safeSearch", http.StatusBadRequest)
			return
		}
		body := `{"enabled":` + strconv.FormatBool(*req.Enabled) + `}`
		resp, err := s.doRequest("PUT", "/control/safesearch/settings", newStringReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		events.Log("adguard", "config_"+req.Type, events.SeverityInfo,
			fmt.Sprintf("%s %s", req.Type, enabledWord(*req.Enabled)))
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "blockedServices":
		if req.Services == nil {
			router.JSONError(w, "services field required for type: blockedServices", http.StatusBadRequest)
			return
		}
		payload := map[string]interface{}{
			"ids": req.Services,
			"schedule": map[string]string{
				"time_zone": "UTC",
			},
		}
		body, _ := json.Marshal(payload)
		resp, err := s.doRequest("PUT", "/control/blocked_services/update", newBytesReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		router.JSON(w, map[string]interface{}{"type": req.Type, "services": req.Services})

	default:
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{
			"error":      "unknown type: " + req.Type,
			"validTypes": validConfigTypes,
		})
	}
}

func (s *Service) handleGetFiltering(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/filtering/status")
}

// Filter represents a filter entry for batch operations
type Filter struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// maxFilterName bounds a blocklist name; maxFilterURL an address already in AdGuard (remove, toggle).
const (
	maxFilterName = 100
	maxFilterURL  = 2048
)

// cleanFilterName trims a blocklist name and checks it: 1-100 characters, no control characters.
func cleanFilterName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxFilterName || !utf8.ValidString(name) {
		return "", false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return name, true
}

// knownFilterURL is the light check for an address that names a list AdGuard already has (remove,
// toggle): bounded and free of control characters. Not SanitizeBlocklistURL — a list added in
// AdGuard itself (http, or a local file) must stay removable.
func knownFilterURL(u string) bool {
	if u == "" || len(u) > maxFilterURL {
		return false
	}
	for _, r := range u {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

var validFilteringActions = []string{"add", "remove", "toggle", "refresh", "addRule", "removeRule"}

// handleFilteringAction handles unified filtering actions
func (s *Service) handleFilteringAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string   `json:"action"`
		Filters []Filter `json:"filters,omitempty"`
		URL     string   `json:"url,omitempty"`
		Name    string   `json:"name,omitempty"`
		Enabled *bool    `json:"enabled,omitempty"`
		Domain  string   `json:"domain,omitempty"` // addRule / removeRule
		Allow   bool     `json:"allow,omitempty"`  // addRule / removeRule: an allow rule, not a block
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate action
	if req.Action == "" {
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{
			"error":        "action field required",
			"validActions": validFilteringActions,
		})
		return
	}

	switch req.Action {
	case "add":
		if len(req.Filters) == 0 {
			router.JSONError(w, "filters field required for action: add", http.StatusBadRequest)
			return
		}
		// Every list is checked before any is added: a public https address (AdGuard downloads
		// it, so never this server or the private/VPN networks) and a bounded name.
		lists := make([]Filter, 0, len(req.Filters))
		for _, f := range req.Filters {
			u, err := helper.SanitizeBlocklistURL(f.URL)
			if err != nil {
				router.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			name, ok := cleanFilterName(f.Name)
			if !ok {
				router.JSONError(w, "Give the list a name (up to 100 characters)", http.StatusBadRequest)
				return
			}
			lists = append(lists, Filter{Name: name, URL: u})
		}
		// Add filters in batch
		var added, failed []string
		for _, f := range lists {
			body, _ := json.Marshal(map[string]interface{}{
				"name":      f.Name,
				"url":       f.URL,
				"whitelist": false,
			})
			resp, err := s.doRequest("POST", "/control/filtering/add_url", newBytesReader(body))
			if err != nil {
				failed = append(failed, f.URL+": "+err.Error())
				continue
			}
			resp.Body.Close()
			if resp.StatusCode >= 400 {
				failed = append(failed, f.URL+": failed")
				continue
			}
			added = append(added, f.URL)
		}
		result := map[string]interface{}{"action": "add", "added": added}
		if len(failed) > 0 {
			result["errors"] = failed
		}
		router.JSON(w, result)

	case "remove":
		if !knownFilterURL(req.URL) {
			router.JSONError(w, "url field required for action: remove", http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(map[string]interface{}{
			"url":       req.URL,
			"whitelist": false,
		})
		resp, err := s.doRequest("POST", "/control/filtering/remove_url", newBytesReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		router.JSON(w, map[string]interface{}{"action": "remove", "url": req.URL})

	case "toggle":
		name, ok := cleanFilterName(req.Name) // set_url replaces the name too, so it's required
		if !knownFilterURL(req.URL) || req.Enabled == nil || !ok {
			router.JSONError(w, "url, name and enabled fields required for action: toggle", http.StatusBadRequest)
			return
		}
		req.Name = name
		body, _ := json.Marshal(map[string]interface{}{
			"url":       req.URL,
			"whitelist": false,
			"data": map[string]interface{}{
				"enabled": *req.Enabled,
				"url":     req.URL,
				"name":    req.Name,
			},
		})
		resp, err := s.doRequest("POST", "/control/filtering/set_url", newBytesReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		router.JSON(w, map[string]interface{}{"action": "toggle", "url": req.URL, "enabled": *req.Enabled})

	case "refresh":
		body := `{"whitelist":false}`
		resp, err := s.doRequest("POST", "/control/filtering/refresh", newStringReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusFailedDependency)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		// Proxy the response (contains updated counts)
		var result interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		router.JSON(w, map[string]interface{}{"action": "refresh", "result": result})

	case "addRule", "removeRule":
		// One rule at a time, through SetCustomRule's locked edit: the domain is checked to be a
		// plain hostname, and nothing else in the list (the panel's client exceptions, rules
		// written by hand in AdGuard) can be lost to a stale copy.
		domain, err := NormalizeDomain(req.Domain) // the clean form is what's saved, logged and returned
		if err == nil {
			err = SetCustomRule(domain, req.Allow, req.Action == "addRule")
		}
		if err != nil {
			adguardEditError(w, err)
			return
		}
		verb := map[string]string{"addRule": "added", "removeRule": "removed"}[req.Action]
		kind := map[bool]string{false: "block", true: "allow"}[req.Allow]
		events.Log("adguard", "rule_"+req.Action, events.SeverityInfo, fmt.Sprintf("%s rule %s: %s", kind, verb, domain))
		router.JSON(w, map[string]interface{}{"action": req.Action, "domain": domain, "allow": req.Allow})

	default:
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{
			"error":        "unknown action: " + req.Action,
			"validActions": validFilteringActions,
		})
	}
}

func (s *Service) handleGetRewrites(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/rewrite/list")
}

var validRewriteActions = []string{"add", "delete", "update"}

// valid reports whether both values are present and pass validRewriteValue.
func (e Rewrite) valid() bool {
	return validRewriteValue(e.Domain) && validRewriteValue(e.Answer)
}

// validRewriteValue accepts a bounded, printable, whitespace-free string — enough to hold
// a domain (incl. wildcards), an IP, or a CNAME answer, while rejecting control chars and
// oversized input. Not a strict domain/IP validator by design (see caller).
func validRewriteValue(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// handleRewriteAction handles the rewrite actions: add, delete, and update (replace one rewrite —
// matched by domain and answer — with another, including on/off, in one AdGuard call, so a
// failed change never leaves the old rewrite deleted).
func (s *Service) handleRewriteAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string  `json:"action"`
		Domain  string  `json:"domain,omitempty"`
		Answer  string  `json:"answer,omitempty"`
		Enabled *bool   `json:"enabled,omitempty"` // update only, required there
		Target  Rewrite `json:"target"`            // update only: the rewrite to replace
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Sanity-check the rewrite values before forwarding them to AdGuard. We deliberately
	// do NOT force a strict domain/IP shape — AdGuard rewrite domains allow wildcards and
	// answers may be an IP or a CNAME — but we reject control chars, whitespace and
	// oversized values so nothing injection-shaped is passed through unvalidated.
	entry := Rewrite{Domain: req.Domain, Answer: req.Answer}
	switch req.Action {
	case "add", "delete":
		if !entry.valid() {
			router.JSONError(w, "valid domain and answer required for action: "+req.Action, http.StatusBadRequest)
			return
		}
		if s.forwardRewrite(w, "POST", "/control/rewrite/"+req.Action, entry) {
			router.JSON(w, map[string]interface{}{"action": req.Action, "domain": req.Domain, "answer": req.Answer})
		}
	case "update":
		// enabled is required: AdGuard's own default for a missing value isn't something to rely on
		if !entry.valid() || !req.Target.valid() || req.Enabled == nil {
			router.JSONError(w, "valid target, domain, answer and enabled required for action: update", http.StatusBadRequest)
			return
		}
		entry.Enabled = req.Enabled
		target := Rewrite{Domain: req.Target.Domain, Answer: req.Target.Answer} // matched by these two only
		body := map[string]Rewrite{"target": target, "update": entry}
		if s.forwardRewrite(w, "PUT", "/control/rewrite/update", body) {
			router.JSON(w, map[string]interface{}{"action": "update", "domain": req.Domain, "answer": req.Answer, "enabled": *req.Enabled})
		}
	case "":
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{"error": "action field required", "validActions": validRewriteActions})
	default:
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{"error": "unknown action: " + req.Action, "validActions": validRewriteActions})
	}
}

// adguardEditError answers a failed rule edit: a bad domain is the caller's (400); anything else
// is AdGuard's, logged here and kept out of the response.
func adguardEditError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrInvalidDomain) {
		router.JSONError(w, "Enter a plain domain name, e.g. ads.example.com", http.StatusBadRequest)
		return
	}
	log.Printf("adguard: rule edit: %v", err)
	router.JSONError(w, "AdGuard request failed — check that AdGuard is running and its credentials in Settings", http.StatusFailedDependency)
}

// forwardRewrite sends one rewrite call to AdGuard. It writes the error response and returns
// false when AdGuard can't be reached or refuses; true means the caller writes the success.
func (s *Service) forwardRewrite(w http.ResponseWriter, method, path string, payload any) bool {
	body, err := json.Marshal(payload)
	if err != nil {
		router.JSONError(w, "invalid rewrite", http.StatusBadRequest)
		return false
	}
	resp, err := s.doRequest(method, path, newBytesReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusFailedDependency)
		return false
	}
	defer resp.Body.Close()
	return !proxyError(w, resp)
}

// Helper functions using stdlib
func newStringReader(s string) io.Reader {
	return strings.NewReader(s)
}

func newBytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}

// Rewrite is one DNS rewrite as AdGuard's API has it. Enabled is sent only on update (an add
// leaves AdGuard's default, on); delete matches by domain and answer.
type Rewrite struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// GetRewrites returns all DNS rewrites
func GetRewrites() ([]Rewrite, error) {
	svc := GetService()
	if svc == nil {
		return nil, fmt.Errorf("adguard service not initialized")
	}
	resp, err := svc.doRequest("GET", "/control/rewrite/list", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for auth errors
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("AdGuard authentication failed. Check credentials in Settings.")
	}

	var rewrites []Rewrite
	if err := json.NewDecoder(resp.Body).Decode(&rewrites); err != nil {
		return nil, err
	}
	return rewrites, nil
}

// AddRewrite adds a DNS rewrite
func AddRewrite(domain, answer string) error {
	svc := GetService()
	if svc == nil {
		return fmt.Errorf("adguard service not initialized")
	}
	body, _ := json.Marshal(Rewrite{Domain: domain, Answer: answer})
	resp, err := svc.doRequest("POST", "/control/rewrite/add", newBytesReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for auth errors
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("AdGuard authentication failed. Check credentials in Settings.")
	}
	return nil
}

// DeleteRewrite removes a DNS rewrite
func DeleteRewrite(domain, answer string) error {
	svc := GetService()
	if svc == nil {
		return fmt.Errorf("adguard service not initialized")
	}
	body, _ := json.Marshal(Rewrite{Domain: domain, Answer: answer})
	resp, err := svc.doRequest("POST", "/control/rewrite/delete", newBytesReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for auth errors
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("AdGuard authentication failed. Check credentials in Settings.")
	}
	return nil
}

// DomainRoute represents a domain route for DNS sync
type DomainRoute struct {
	Domain string
}

// SyncDomainRewrites ensures DNS rewrites exist for all domains pointing to targetIP
// Only adds/updates rewrites for managed domains - does NOT delete other rewrites
// Returns a list of errors for domains that failed
func SyncDomainRewrites(domains []DomainRoute, targetIP string) []string {
	errors := []string{}

	// Get existing rewrites
	existing, err := GetRewrites()
	if err != nil {
		errors = append(errors, "failed to get existing rewrites: "+err.Error())
		return errors
	}

	// Build map of existing rewrites
	existingMap := make(map[string]string)
	for _, rw := range existing {
		existingMap[rw.Domain] = rw.Answer
	}

	// Add/update rewrites for each domain (all point to targetIP)
	for _, route := range domains {
		if current, exists := existingMap[route.Domain]; exists {
			if current == targetIP {
				continue // Already correct
			}
			// Delete wrong rewrite first (domain exists but points elsewhere)
			if err := DeleteRewrite(route.Domain, current); err != nil {
				errors = append(errors, route.Domain+": failed to delete old rewrite: "+err.Error())
			}
		}
		// Add correct rewrite
		if err := AddRewrite(route.Domain, targetIP); err != nil {
			errors = append(errors, route.Domain+": failed to add rewrite: "+err.Error())
		}
	}

	return errors
}

// DeleteDomainRewrite removes the DNS rewrite for a specific domain pointing to targetIP
func DeleteDomainRewrite(domain, targetIP string) error {
	return DeleteRewrite(domain, targetIP)
}
