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
)

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

	// Session
	if timeout, err := getSetting("session_timeout"); err == nil {
		result["session_timeout"] = timeout
	} else {
		result["session_timeout"] = strconv.Itoa(config.GetSessionConfig().TimeoutHours)
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
