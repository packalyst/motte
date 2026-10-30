package settings

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
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
	// web_cloudflare_only toggle changes so the cf_only table takes effect live.
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

// UpdateSettingsRequest for PUT /api/settings
type UpdateSettingsRequest struct {
	HeadscaleURL            *string `json:"headscale_url,omitempty"` // Public URL (editable)
	AdGuardUsername         *string `json:"adguard_username,omitempty"`
	AdGuardPassword         *string `json:"adguard_password,omitempty"`
	AdGuardDashboardEnabled *bool   `json:"adguard_dashboard_enabled,omitempty"`
	AdGuardQuerylogSize     *int    `json:"adguard_querylog_size,omitempty"` // querylog.size_memory in MB
	SessionTimeout          *string `json:"session_timeout,omitempty"`
	IdleLockMinutes         *int    `json:"idle_lock_minutes,omitempty"`      // 0 = disable the idle lock
	WebCloudflareOnly       *bool   `json:"web_cloudflare_only,omitempty"`    // true = only Cloudflare edge IPs reach 443 (L3) and get an answer on 80 (Traefik gate)
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

	// Cloudflare-only web access (L3). `_available` tells the UI whether the toggle may be
	// turned on — restricting 80/443 to Cloudflare only makes sense (and is only safe) when
	// the domain is actually proxied through Cloudflare (set at setup).
	result["web_cloudflare_only"] = GetWebCloudflareOnly()
	result["web_cloudflare_only_available"] = domainBehindCloudflare()

	// Session
	result["session_timeout"] = strconv.Itoa(SessionTimeoutHours())
	result["session_timeout_choices"] = helper.SessionTimeoutHours
	result["idle_lock_minutes"] = IdleLockMinutes()
	result["idle_lock_choices"] = helper.IdleLockMinutes

	// Aggregate-metrics retention window (days)
	result["metrics_retention_days"] = GetRetentionDays()

	result["display_timezone"] = DisplayTimezone()

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
	// Checked before anything is saved: a timeout of 0 or less would end every new sign-in at once,
	// the owner's too, so only the offered lengths are taken.
	if req.SessionTimeout != nil {
		if h, err := strconv.Atoi(*req.SessionTimeout); err != nil || !slices.Contains(helper.SessionTimeoutHours, h) {
			router.JSONError(w, fmt.Sprintf("session timeout must be one of %v hours", helper.SessionTimeoutHours), http.StatusBadRequest)
			return
		}
	}
	if req.IdleLockMinutes != nil && !slices.Contains(helper.IdleLockMinutes, *req.IdleLockMinutes) {
		router.JSONError(w, fmt.Sprintf("idle lock must be one of %v minutes", helper.IdleLockMinutes), http.StatusBadRequest)
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

	// Cloudflare-only web access (L3). Turning it ON restricts ports 80/443 to Cloudflare's
	// edge ranges via the cf_only nftables table. Guarded: only allowed once SSL/a public
	// domain is configured, otherwise closing 80/443 to non-Cloudflare cuts off all web access.
	if req.WebCloudflareOnly != nil {
		if *req.WebCloudflareOnly && !domainBehindCloudflare() {
			router.JSONError(w, "Your domain isn't marked as behind Cloudflare (set during setup) — restricting web access to Cloudflare would cut off all visitors. Put the domain behind Cloudflare first.", http.StatusBadRequest)
			return
		}
		if err := SetWebCloudflareOnly(*req.WebCloudflareOnly); err != nil {
			router.JSONError(w, "Failed to save web_cloudflare_only: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if *req.WebCloudflareOnly {
			log.Printf("Cloudflare-only web access ENABLED (443 restricted to Cloudflare, 80 gated in Traefik)")
			events.Log("settings", "web_cloudflare_only", events.SeverityWarning, "Cloudflare-only web access enabled — HTTPS (443) now reachable only from Cloudflare (plus localhost, Docker and the VPNs); on HTTP (80) anyone else gets no answer, except Let's Encrypt's certificate check")
		} else {
			log.Printf("Cloudflare-only web access DISABLED (80/443 open)")
			events.Log("settings", "web_cloudflare_only", events.SeverityInfo, "Cloudflare-only web access disabled — ports 80/443 open to all sources")
		}
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

	// Idle lock (minutes of inactivity before the UI locks and requires re-auth; checked above).
	// Opt-in: 0 (off) until an admin sets it.
	if req.IdleLockMinutes != nil {
		v := *req.IdleLockMinutes
		if err := setSetting("idle_lock_minutes", strconv.Itoa(v)); err != nil {
			router.JSONError(w, "Failed to save idle_lock_minutes: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated idle_lock_minutes to %d", v)
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

// GetWebCloudflareOnly reports whether the web ports are restricted to Cloudflare: 443 by the
// cf_only nftables table (L3), 80 by Traefik's gate (which lets Let's Encrypt's HTTP challenge
// through). Default OFF — the web ports are open until an operator explicitly turns it on.
func GetWebCloudflareOnly() bool {
	v, err := GetSetting("web_cloudflare_only")
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v), "on")
}

// SetWebCloudflareOnly persists the Cloudflare-only-web toggle ("on"/"off").
func SetWebCloudflareOnly(on bool) error {
	v := "off"
	if on {
		v = "on"
	}
	return SetSetting("web_cloudflare_only", v)
}

// domainBehindCloudflare reports whether the SSL domain is proxied through Cloudflare
// (the operator's answer at setup, persisted as BEHIND_CLOUDFLARE). Cloudflare-only web
// access may only be turned ON when true — otherwise restricting 80/443 to Cloudflare
// would cut off all visitors.
func domainBehindCloudflare() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("BEHIND_CLOUDFLARE")), "true")
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

// DisplayTimezone is how the UI shows dates: "browser" (default, each viewer's own zone) or an
// IANA zone name. Display only; sent to every signed-in user with /api/auth/me.
func DisplayTimezone() string {
	if tz, err := getSetting("display_timezone"); err == nil && tz != "" {
		return tz
	}
	return "browser"
}

// GetSettingInt exports the integer getter for other packages
func GetSettingInt(key string, defaultVal int) int {
	return getSettingInt(key, defaultVal)
}

// settingChoice is the saved int setting when it is one of choices, else def (a value saved before
// the save check, or edited into the database, is never used).
func settingChoice(key string, choices []int, def int) int {
	if v, err := getSetting(key); err == nil {
		if i, err := strconv.Atoi(v); err == nil && slices.Contains(choices, i) {
			return i
		}
	}
	return def
}

// SessionTimeoutHours is how many hours a new sign-in lasts (helper.SessionTimeoutHours; default
// the configured one).
func SessionTimeoutHours() int {
	return settingChoice("session_timeout", helper.SessionTimeoutHours, config.GetSessionConfig().TimeoutHours)
}

// IdleLockMinutes is how many idle minutes lock the screen, 0 for never (helper.IdleLockMinutes).
func IdleLockMinutes() int {
	return settingChoice("idle_lock_minutes", helper.IdleLockMinutes, 0)
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

// trustedNetworksKey holds the admin's extra trusted networks (JSON list); see helper.TrustedNetworks.
const trustedNetworksKey = "trusted_networks"

// LoadTrustedNetworks loads the extra trusted networks into memory. The first time (nothing stored
// yet) they are seeded from IGNORE_NETWORKS and saved, so later edits in Settings are what count.
func LoadTrustedNetworks() {
	var extras []string
	stored, err := getSetting(trustedNetworksKey)
	switch {
	case err == nil:
		if json.Unmarshal([]byte(stored), &extras) != nil {
			log.Printf("settings: ignoring unreadable %s", trustedNetworksKey)
			extras = nil
		}
	case !errors.Is(err, sql.ErrNoRows):
		// DB trouble: run with the VPN ranges only, and never overwrite the saved list.
		log.Printf("settings: could not read trusted networks: %v", err)
	default:
		seed, serr := helper.TrustedExtrasFrom(helper.ParseStringList(helper.GetEnvOptional("IGNORE_NETWORKS", "")))
		if serr != nil {
			log.Printf("settings: IGNORE_NETWORKS not used as trusted networks: %v", serr)
		}
		extras = seed
		if err := SetTrustedNetworks(extras); err != nil {
			log.Printf("settings: could not save trusted networks: %v", err)
		}
	}
	helper.SetTrustedExtras(extras)
}

// SetTrustedNetworks persists the extra trusted networks (already validated by
// helper.TrustedExtrasFrom).
func SetTrustedNetworks(extras []string) error {
	if extras == nil {
		extras = []string{}
	}
	b, err := json.Marshal(extras)
	if err != nil {
		return err
	}
	return setSetting(trustedNetworksKey, string(b))
}
