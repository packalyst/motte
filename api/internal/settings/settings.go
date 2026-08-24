package settings

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"api/internal/adguard"
	"api/internal/config"
	"api/internal/database"
	"api/internal/events"
	"api/internal/headscale"
	"api/internal/helper"
	"api/internal/router"
)

// Service provider callbacks (set by main.go to avoid import cycles)
var (
	GetTraefikConfig   func() interface{}
	GetTraefikVPNOnly  func() string
	GetGeoSettings     func() interface{}
	GetGeoStatus       func() interface{}
	GetVPNRouterStatus func() interface{}

	// RequestFirewallApply asks the nftables service to re-apply all tables. Set by
	// main.go (function pointer avoids a settings→nftables import cycle). Used when the
	// api_direct_access toggle changes so the panel-access table takes effect live.
	RequestFirewallApply func()

	// OnRetentionChange runs a prune sweep immediately after the retention setting is
	// saved. Set by main.go (function pointer avoids a settings→retention import cycle).
	OnRetentionChange func()
)

// RetentionKey holds the aggregate-metrics retention window (days). DefaultRetentionDays
// is the fallback when unset.
const (
	RetentionKey         = "metrics_retention_days"
	DefaultRetentionDays = 90
)

// validTimezone accepts "browser" or an IANA-style zone name (letters, digits, and the
// separators / _ + - only). It's a charset guard, not a tz-database lookup — the value is
// display-only and applied client-side, never used in server-side time math.
func validTimezone(tz string) bool {
	for _, r := range tz {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '/' || r == '_' || r == '+' || r == '-':
		default:
			return false
		}
	}
	return true
}

// GetRetentionDays returns the aggregate-retention window in days, falling back to the
// default when unset or out of range. It drives the central retention sweep, which is
// the single window for every aggregate table except traffic_usage.
func GetRetentionDays() int {
	d := getSettingInt(RetentionKey, DefaultRetentionDays)
	if d < 1 || d > 3650 {
		return DefaultRetentionDays
	}
	return d
}

// Service handles settings management
type Service struct{}

// New creates a new settings service
func New() *Service {
	return &Service{}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetSettings":    s.handleGetSettings,
		"SelectSettings": s.handleSelectSettings,
		"UpdateSettings": s.handleUpdateSettings,
	}
}

// SettingsResponse for GET /api/settings
type SettingsResponse struct {
	// Headscale
	HeadscaleAPIURL string `json:"headscale_api_url"` // Internal API URL (readonly, auto-detected)
	HeadscaleURL    string `json:"headscale_url"`     // Public URL for Tailscale clients
	HeadscaleAPIKey bool   `json:"headscale_api_key"` // true if set, don't expose actual key

	// AdGuard
	AdGuardUsername         string `json:"adguard_username"`
	AdGuardPassword         bool   `json:"adguard_password"`          // true if set
	AdGuardDashboardEnabled bool   `json:"adguard_dashboard_enabled"` // true = 0.0.0.0, false = 127.0.0.1
	AdGuardDashboardURL     string `json:"adguard_dashboard_url"`     // URL when dashboard enabled

	// Session
	SessionTimeout string `json:"session_timeout"`

	// Port Scanner
	ScannerPortStart  int `json:"scanner_port_start"`
	ScannerPortEnd    int `json:"scanner_port_end"`
	ScannerConcurrent int `json:"scanner_concurrent"`
	ScannerPauseMs    int `json:"scanner_pause_ms"`
	ScannerTimeoutMs  int `json:"scanner_timeout_ms"`

	// Traefik (aggregated)
	Traefik     interface{} `json:"traefik,omitempty"`
	VPNOnlyMode string      `json:"vpn_only_mode,omitempty"`

	// Geolocation (aggregated)
	Geo       interface{} `json:"geo,omitempty"`
	GeoStatus interface{} `json:"geo_status,omitempty"`

	// VPN Router (aggregated)
	Router interface{} `json:"router,omitempty"`
}

// UpdateSettingsRequest for PUT /api/settings
type UpdateSettingsRequest struct {
	HeadscaleURL            *string `json:"headscale_url,omitempty"` // Public URL (editable)
	AdGuardUsername         *string `json:"adguard_username,omitempty"`
	AdGuardPassword         *string `json:"adguard_password,omitempty"`
	AdGuardDashboardEnabled *bool   `json:"adguard_dashboard_enabled,omitempty"`
	AdGuardQuerylogSize     *int    `json:"adguard_querylog_size,omitempty"` // querylog.size_memory in MB
	SessionTimeout          *string `json:"session_timeout,omitempty"`
	APIDirectAccess         *bool   `json:"api_direct_access,omitempty"`      // false = close the API port to the public internet (L3)
	MetricsRetentionDays    *int    `json:"metrics_retention_days,omitempty"` // window (days) for all aggregate tables
	DisplayTimezone         *string `json:"display_timezone,omitempty"`       // "browser" or an IANA zone; UI display only

	// Port Scanner
	ScannerPortStart  *int `json:"scanner_port_start,omitempty"`
	ScannerPortEnd    *int `json:"scanner_port_end,omitempty"`
	ScannerConcurrent *int `json:"scanner_concurrent,omitempty"`
	ScannerPauseMs    *int `json:"scanner_pause_ms,omitempty"`
	ScannerTimeoutMs  *int `json:"scanner_timeout_ms,omitempty"`
}

// handleGetSettings returns all settings (GET /api/settings)
func (s *Service) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, s.buildSettingsMap())
}

// SelectSettingsRequest for POST /api/settings (selective fetch)
type SelectSettingsRequest struct {
	Keys []string `json:"keys"`
}

// handleSelectSettings returns only requested keys (POST /api/settings)
func (s *Service) handleSelectSettings(w http.ResponseWriter, r *http.Request) {
	var req SelectSettingsRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if len(req.Keys) == 0 {
		router.JSONError(w, "keys required", http.StatusBadRequest)
		return
	}

	all := s.buildSettingsMap()
	result := make(map[string]interface{})
	for _, key := range req.Keys {
		if val, ok := all[key]; ok {
			result[key] = val
		}
	}
	router.JSON(w, result)
}

// buildSettingsMap returns all settings as a map
func (s *Service) buildSettingsMap() map[string]interface{} {
	result := make(map[string]interface{})

	// Headscale
	if url, err := getSetting("headscale_api_url"); err == nil {
		result["headscale_api_url"] = url
	}
	if url, err := getSetting("headscale_url"); err == nil {
		result["headscale_url"] = url
	}
	if _, err := getSettingEncrypted("headscale_api_key"); err == nil {
		result["headscale_api_key"] = true
	} else {
		result["headscale_api_key"] = false
	}

	// AdGuard
	if username, err := getSetting("adguard_username"); err == nil {
		result["adguard_username"] = username
	}
	if _, err := getSettingEncrypted("adguard_password"); err == nil {
		result["adguard_password"] = true
	} else {
		result["adguard_password"] = false
	}

	configPath := os.Getenv("ADGUARD_CONFIG")
	if configPath != "" {
		if data, err := os.ReadFile(configPath); err == nil {
			content := string(data)
			// Dashboard enabled check
			dashEnabled := strings.Contains(content, "address: 0.0.0.0:")
			result["adguard_dashboard_enabled"] = dashEnabled
			if dashEnabled {
				serverIP := os.Getenv("SERVER_IP")
				adguardPort := os.Getenv("ADGUARD_PORT")
				if serverIP != "" && adguardPort != "" {
					result["adguard_dashboard_url"] = "http://" + serverIP + ":" + adguardPort
				}
			}
			// Querylog size_memory
			if val, err := helper.GetYAMLPath(content, "querylog.size_memory"); err == nil {
				if size, ok := val.(int); ok {
					result["adguard_querylog_size"] = size
				}
			}
		}
	}

	// Panel direct-IP access (L3). `_domain_set` tells the UI whether the toggle may be
	// turned off — closing the API port is only safe once a domain gives another way in.
	result["api_direct_access"] = GetAPIDirectAccess()
	result["api_direct_access_domain_set"] = panelDomainConfigured()

	// Session
	if timeout, err := getSetting("session_timeout"); err == nil {
		result["session_timeout"] = timeout
	} else {
		result["session_timeout"] = strconv.Itoa(config.GetSessionConfig().TimeoutHours)
	}

	// Aggregate-metrics retention window (days)
	result["metrics_retention_days"] = GetRetentionDays()

	// Display timezone (UI only): "browser" (default) or an IANA zone name
	if tz, err := getSetting("display_timezone"); err == nil && tz != "" {
		result["display_timezone"] = tz
	} else {
		result["display_timezone"] = "browser"
	}

	// Scanner
	result["scanner_port_start"] = getSettingInt("scanner_port_start", 1)
	result["scanner_port_end"] = getSettingInt("scanner_port_end", 5000)
	result["scanner_concurrent"] = getSettingInt("scanner_concurrent", 100)
	result["scanner_pause_ms"] = getSettingInt("scanner_pause_ms", 0)
	result["scanner_timeout_ms"] = getSettingInt("scanner_timeout_ms", 500)

	// Traefik (aggregated)
	if GetTraefikConfig != nil {
		result["traefik"] = GetTraefikConfig()
	}
	if GetTraefikVPNOnly != nil {
		result["vpn_only_mode"] = GetTraefikVPNOnly()
	}

	// Geolocation (aggregated)
	if GetGeoSettings != nil {
		result["geo"] = GetGeoSettings()
	}
	if GetGeoStatus != nil {
		result["geo_status"] = GetGeoStatus()
	}

	// VPN Router (aggregated)
	if GetVPNRouterStatus != nil {
		result["router"] = GetVPNRouterStatus()
	}

	return result
}

func (s *Service) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req UpdateSettingsRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Update Headscale public URL (api_url is readonly, set during setup)
	headscaleRestartRequired := false
	nodesExpired := 0
	if req.HeadscaleURL != nil {
		// Test if headscale is reachable at the new URL before applying
		if err := headscale.TestURL(*req.HeadscaleURL); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := setSetting("headscale_url", *req.HeadscaleURL); err != nil {
			router.JSONError(w, "Failed to save headscale_url: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated headscale_url to %s", *req.HeadscaleURL)

		// Update headscale config.yaml
		configPath := helper.GetEnv("HEADSCALE_CONFIG_PATH")
		if configPath != "" {
			if err := headscale.UpdateConfig(configPath, *req.HeadscaleURL); err != nil {
				log.Printf("Warning: Failed to update Headscale config: %v", err)
			} else {
				headscaleRestartRequired = true
				log.Printf("Updated Headscale config, restart required")

				// Expire all nodes so they show as needing re-authentication
				if count, err := headscale.ExpireAllNodes(); err != nil {
					log.Printf("Warning: Failed to expire nodes: %v", err)
				} else {
					nodesExpired = count
					log.Printf("Expired %d nodes due to URL change", count)
				}
			}
		}
	}

	// Panel direct-IP access (L3). Turning it OFF closes the API port to the public
	// internet via the panel-access nftables table. Guarded: it may only be turned off
	// once a domain is configured, otherwise the operator would lose their only way in.
	if req.APIDirectAccess != nil {
		if !*req.APIDirectAccess && !panelDomainConfigured() {
			router.JSONError(w, "Set up a domain (SSL_DOMAIN or ADMIN_DOMAIN) before closing direct IP access — otherwise you'd lock yourself out of the panel.", http.StatusBadRequest)
			return
		}
		if err := SetAPIDirectAccess(*req.APIDirectAccess); err != nil {
			router.JSONError(w, "Failed to save api_direct_access: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if *req.APIDirectAccess {
			log.Printf("Panel direct IP access ENABLED (API port open)")
			events.Log("settings", "api_direct_access", events.SeverityInfo, "Panel direct IP access enabled (API port open to the network)")
		} else {
			log.Printf("Panel direct IP access DISABLED (API port closed to the public internet)")
			events.Log("settings", "api_direct_access", events.SeverityWarning, "Panel direct IP access disabled — API port now reachable only via the domain, localhost and WireGuard")
		}
		// Re-apply the firewall so the panel-access table reflects the new state immediately.
		if RequestFirewallApply != nil {
			RequestFirewallApply()
		}
	}

	// Update AdGuard settings
	adguardRestartRequired := false
	if req.AdGuardUsername != nil {
		if err := setSetting("adguard_username", *req.AdGuardUsername); err != nil {
			router.JSONError(w, "Failed to save adguard_username: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated adguard_username")
	}
	if req.AdGuardPassword != nil {
		if err := setSettingEncrypted("adguard_password", *req.AdGuardPassword); err != nil {
			router.JSONError(w, "Failed to save adguard_password: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Mark that adguard password has been configured
		_ = setSetting("adguard_pass_changed", "true")
		log.Printf("Updated adguard_password")
	}

	// Update AdGuard YAML config if needed
	adguardConfigPath := helper.GetEnvOptional("ADGUARD_CONFIG", "")
	if adguardConfigPath != "" {
		if req.AdGuardUsername != nil && req.AdGuardPassword != nil {
			if restart, err := adguard.UpdateCredentials(adguardConfigPath, *req.AdGuardUsername, *req.AdGuardPassword); err != nil {
				log.Printf("Warning: Failed to update AdGuard config: %v", err)
			} else if restart {
				adguardRestartRequired = true
			}
		}
		if req.AdGuardDashboardEnabled != nil {
			if err := adguard.UpdateDashboard(adguardConfigPath, *req.AdGuardDashboardEnabled); err != nil {
				log.Printf("Warning: Failed to update AdGuard dashboard: %v", err)
			} else {
				adguardRestartRequired = true
			}
		}
		if req.AdGuardQuerylogSize != nil {
			if err := adguard.UpdateQuerylogSize(adguardConfigPath, *req.AdGuardQuerylogSize); err != nil {
				log.Printf("Warning: Failed to update AdGuard querylog size: %v", err)
			} else {
				adguardRestartRequired = true
			}
		}
	}

	// Update Session settings
	if req.SessionTimeout != nil {
		if err := setSetting("session_timeout", *req.SessionTimeout); err != nil {
			router.JSONError(w, "Failed to save session_timeout: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated session_timeout to %s hours", *req.SessionTimeout)
	}

	// Aggregate-metrics retention (days). Drives the central prune sweep across all
	// aggregate tables (fleet_metrics, fw/l7 samples, log_rollups). Saving runs the
	// sweep immediately so a lowered window trims right away; the daily ticker in
	// main.go keeps it enforced afterwards.
	if req.MetricsRetentionDays != nil {
		d := *req.MetricsRetentionDays
		if d < 1 || d > 3650 {
			router.JSONError(w, "metrics_retention_days must be between 1 and 3650", http.StatusBadRequest)
			return
		}
		if err := setSettingInt(RetentionKey, d); err != nil {
			router.JSONError(w, "Failed to save metrics_retention_days: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated metrics_retention_days to %d", d)
		if OnRetentionChange != nil {
			go OnRetentionChange() // best-effort immediate prune; don't block the response
		}
	}

	// Display timezone (UI only): "browser" (default) or an IANA zone name. Stored as an
	// opaque string — the browser applies it when formatting; the server never uses it.
	if req.DisplayTimezone != nil {
		tz := strings.TrimSpace(*req.DisplayTimezone)
		if tz == "" || len(tz) > 64 || !validTimezone(tz) {
			router.JSONError(w, "invalid display_timezone", http.StatusBadRequest)
			return
		}
		if err := setSetting("display_timezone", tz); err != nil {
			router.JSONError(w, "Failed to save display_timezone: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated display_timezone to %s", tz)
	}

	// Update Scanner settings
	if req.ScannerPortStart != nil {
		setSettingInt("scanner_port_start", *req.ScannerPortStart)
	}
	if req.ScannerPortEnd != nil {
		setSettingInt("scanner_port_end", *req.ScannerPortEnd)
	}
	if req.ScannerConcurrent != nil {
		setSettingInt("scanner_concurrent", *req.ScannerConcurrent)
	}
	if req.ScannerPauseMs != nil {
		setSettingInt("scanner_pause_ms", *req.ScannerPauseMs)
	}
	if req.ScannerTimeoutMs != nil {
		setSettingInt("scanner_timeout_ms", *req.ScannerTimeoutMs)
	}

	events.Log("settings", "settings_updated", events.SeverityInfo, "Settings updated")

	router.JSON(w, map[string]interface{}{
		"status":                   "ok",
		"adguardRestartRequired":   adguardRestartRequired,
		"headscaleRestartRequired": headscaleRestartRequired,
		"nodesExpired":             nodesExpired,
	})
}

// Helper functions for settings

func getSetting(key string) (string, error) {
	db, err := database.GetDB()
	if err != nil {
		return "", err
	}

	var value string
	err = db.QueryRow("SELECT value FROM settings WHERE key = ? AND encrypted = 0", key).Scan(&value)
	return value, err
}

func getSettingInt(key string, defaultVal int) int {
	if val, err := getSetting(key); err == nil {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func setSettingInt(key string, value int) error {
	return setSetting(key, strconv.Itoa(value))
}

func setSetting(key, value string) error {
	db, err := database.GetDB()
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		INSERT INTO settings (key, value, encrypted, updated_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = ?, encrypted = 0, updated_at = CURRENT_TIMESTAMP
	`, key, value, value)
	return err
}

func getSettingEncrypted(key string) (string, error) {
	db, err := database.GetDB()
	if err != nil {
		return "", err
	}

	var value string
	var encrypted bool
	err = db.QueryRow("SELECT value, encrypted FROM settings WHERE key = ?", key).Scan(&value, &encrypted)
	if err != nil {
		return "", err
	}

	if encrypted {
		return helper.Decrypt(value)
	}

	return value, nil
}

func setSettingEncrypted(key, value string) error {
	db, err := database.GetDB()
	if err != nil {
		return err
	}

	encrypted, err := helper.Encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt value: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO settings (key, value, encrypted, updated_at)
		VALUES (?, ?, 1, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = ?, encrypted = 1, updated_at = CURRENT_TIMESTAMP
	`, key, encrypted, encrypted)
	return err
}

// GetTraefikFWBlock reports whether the firewall block-list should be enforced at the
// Traefik/sentinel (L7) layer, so blocks apply to Cloudflare-proxied traffic too. Default
// ON — only an explicit "off" disables it.
func GetTraefikFWBlock() bool {
	v, err := GetSetting("traefik_fw_block")
	if err != nil {
		return true
	}
	return v != "off"
}

// SetTraefikFWBlock persists the L7 firewall-block toggle.
func SetTraefikFWBlock(on bool) error {
	v := "off"
	if on {
		v = "on"
	}
	return SetSetting("traefik_fw_block", v)
}

// GetAPIDirectAccess reports whether the panel API is reachable by direct IP (L3). Default
// ON — the API is IP-reachable until an operator explicitly turns it off (which the
// panel-access nftables table then enforces by dropping the API port from the public
// internet). A missing setting means ON, so a fresh/domain-less install is never locked out.
func GetAPIDirectAccess() bool {
	v, err := GetSetting("api_direct_access")
	if err != nil {
		return true
	}
	return !strings.EqualFold(strings.TrimSpace(v), "off")
}

// SetAPIDirectAccess persists the direct-IP-access toggle ("on"/"off").
func SetAPIDirectAccess(on bool) error {
	v := "off"
	if on {
		v = "on"
	}
	return SetSetting("api_direct_access", v)
}

// panelDomainConfigured reports whether a domain is set for the panel (SSL_DOMAIN or
// ADMIN_DOMAIN). Direct IP access may only be turned OFF when one exists — otherwise
// closing the API port would remove the operator's only way in.
func panelDomainConfigured() bool {
	if d := strings.TrimSpace(os.Getenv("SSL_DOMAIN")); d != "" {
		return true
	}
	if d := strings.TrimSpace(os.Getenv("ADMIN_DOMAIN")); d != "" {
		return true
	}
	return false
}

// GetSetting exports the getter for other packages
func GetSetting(key string) (string, error) {
	return getSetting(key)
}

// GetSettingEncrypted exports the encrypted getter for other packages
func GetSettingEncrypted(key string) (string, error) {
	return getSettingEncrypted(key)
}

// SetSetting exports the setter for other packages
func SetSetting(key, value string) error {
	return setSetting(key, value)
}

// SetSettingEncrypted exports the encrypted setter for other packages
func SetSettingEncrypted(key, value string) error {
	return setSettingEncrypted(key, value)
}

// GetSettingInt exports the integer getter for other packages
func GetSettingInt(key string, defaultVal int) int {
	return getSettingInt(key, defaultVal)
}

// DeleteSetting removes a setting from the database
func DeleteSetting(key string) error {
	db, err := database.GetDB()
	if err != nil {
		return err
	}

	_, err = db.Exec("DELETE FROM settings WHERE key = ?", key)
	return err
}
