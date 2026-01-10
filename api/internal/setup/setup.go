package setup

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"api/internal/auth"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/settings"
)

// Service handles initial setup
type Service struct {
	auth    *auth.Service
	setupMu sync.Mutex // Protects concurrent setup attempts
}

// requireAuthIfCompleted validates authentication if setup is completed
// Returns true if request should continue, false if an error response was sent
func (s *Service) requireAuthIfCompleted(w http.ResponseWriter, r *http.Request) bool {
	status, _ := s.GetStatus()
	if !status.Completed {
		return true // No auth required during setup
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	token = strings.TrimPrefix(token, "Bearer ")

	if s.auth == nil {
		router.JSONError(w, "Auth service not available", http.StatusInternalServerError)
		return false
	}

	if _, err := s.auth.ValidateSession(token); err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	return true
}

// SetupStatus represents the setup state
type SetupStatus struct {
	Completed           bool `json:"completed"`
	HasAdmin            bool `json:"hasAdmin"`
	HasHeadscale        bool `json:"hasHeadscale"`
	AdguardPassChanged  bool `json:"adguardPassChanged"`
}

// SetupRequest represents the setup wizard data
type SetupRequest struct {
	// Admin user
	AdminUsername string `json:"adminUsername"`
	AdminPassword string `json:"adminPassword"`

	// Headscale configuration
	HeadscaleAPIURL string `json:"headscaleApiUrl"` // Internal API URL (auto-detected)
	HeadscaleURL    string `json:"headscaleUrl"`    // Public URL for Tailscale clients
	HeadscaleAPIKey string `json:"headscaleApiKey"`
}

// New creates a new setup service
func New() *Service {
	return &Service{
		auth: auth.GetService(),
	}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetStatus":        s.handleGetStatus,
		"TestHeadscale":    s.handleTestHeadscale,
		"CompleteSetup":    s.handleCompleteSetup,
		"DetectHeadscale":  s.handleDetectHeadscale,
		"GenerateAPIKey":   s.handleGenerateAPIKey,
	}
}

// detectHeadscaleURL finds headscale by querying Docker socket
func detectHeadscaleURL() (string, error) {
	// Create HTTP client that connects to Docker (via socket or proxy)
	client := helper.NewDockerHTTPClientWithTimeout(helper.DockerQuickTimeout)

	// Query Docker API for headscale container
	resp, err := client.Get("http://docker/containers/headscale/json")
	if err != nil {
		return "", fmt.Errorf("failed to query Docker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("headscale container not found")
	}

	var container struct {
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
		} `json:"NetworkSettings"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&container); err != nil {
		return "", fmt.Errorf("failed to parse container info: %v", err)
	}

	// Find the port mapping for 8080/tcp (headscale's internal port)
	if ports, ok := container.NetworkSettings.Ports["8080/tcp"]; ok && len(ports) > 0 {
		hostPort := ports[0].HostPort
		hostIP := ports[0].HostIP
		if hostIP == "" || hostIP == "0.0.0.0" {
			hostIP = "127.0.0.1"
		}
		return fmt.Sprintf("http://%s:%s", hostIP, hostPort), nil
	}

	return "", fmt.Errorf("headscale port mapping not found")
}

// generateHeadscaleAPIKey creates a new API key via Docker API exec
func generateHeadscaleAPIKey() (string, error) {
	output, err := dockerExec("headscale", []string{"headscale", "apikeys", "create", "-o", "json"})
	if err != nil {
		return "", err
	}

	// Output is a JSON string like "key_value_here"
	key := strings.Trim(strings.TrimSpace(output), "\"")
	if key == "" {
		return "", fmt.Errorf("empty API key returned")
	}

	return key, nil
}

// demuxDockerStream reads Docker's multiplexed stream format
func demuxDockerStream(r io.Reader) (string, error) {
	var result strings.Builder
	header := make([]byte, 8)

	for {
		_, err := io.ReadFull(r, header)
		if err == io.EOF {
			break
		}
		if err != nil {
			return result.String(), nil // Return what we have
		}

		// header[0] = stream type (0=stdin, 1=stdout, 2=stderr)
		// header[4:8] = size (big endian)
		size := int(header[4])<<24 | int(header[5])<<16 | int(header[6])<<8 | int(header[7])

		if size > 0 {
			data := make([]byte, size)
			_, err := io.ReadFull(r, data)
			if err != nil {
				return result.String(), nil
			}
			result.Write(data)
		}
	}

	return result.String(), nil
}

func (s *Service) handleDetectHeadscale(w http.ResponseWriter, r *http.Request) {
	url, err := detectHeadscaleURL()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	router.JSON(w, map[string]string{"url": url})
}

func (s *Service) handleGenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	status, _ := s.GetStatus()

	if status.Completed {
		// After setup - require authentication
		if !s.requireAuthIfCompleted(w, r) {
			return
		}

		// Check if current key expires in more than 7 days
		expiresIn, err := getHeadscaleKeyExpiration()
		if err == nil && expiresIn > 7*24*time.Hour {
			router.JSONError(w, fmt.Sprintf("API key still valid for %d days, regeneration not needed", int(expiresIn.Hours()/24)), http.StatusBadRequest)
			return
		}
		log.Printf("Regenerating API key (current expires in %v)", expiresIn)
	} else {
		// Before setup - check if we already have a pending key in DB
		if existingKey, err := settings.GetSettingEncrypted("headscale_api_key_pending"); err == nil && existingKey != "" {
			// Return existing pending key
			router.JSON(w, map[string]string{"apiKey": existingKey})
			return
		}
	}

	// Generate new key
	key, err := generateHeadscaleAPIKey()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !status.Completed {
		// Before setup - save as pending key (will be moved to headscale_api_key on complete)
		if err := settings.SetSettingEncrypted("headscale_api_key_pending", key); err != nil {
			log.Printf("Warning: failed to save pending API key: %v", err)
		}
	} else {
		// After setup - save directly as the active key
		if err := settings.SetSettingEncrypted("headscale_api_key", key); err != nil {
			router.JSONError(w, "Failed to save API key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("API key regenerated and saved")
	}

	router.JSON(w, map[string]string{"apiKey": key})
}

// getHeadscaleKeyExpiration checks when the current API key expires
func getHeadscaleKeyExpiration() (time.Duration, error) {
	// Get current key from DB
	currentKey, err := settings.GetSettingEncrypted("headscale_api_key")
	if err != nil {
		return 0, fmt.Errorf("no API key configured")
	}

	// Extract prefix (first part before the dot)
	parts := strings.Split(currentKey, ".")
	if len(parts) < 1 {
		return 0, fmt.Errorf("invalid key format")
	}
	prefix := parts[0]

	// Query headscale for key info via Docker API
	output, err := dockerExec("headscale", []string{"headscale", "apikeys", "list", "-o", "json"})
	if err != nil {
		return 0, fmt.Errorf("failed to list API keys: %v", err)
	}

	var keys []struct {
		Prefix     string `json:"prefix"`
		Expiration struct {
			Seconds int64 `json:"seconds"`
		} `json:"expiration"`
	}
	if err := json.Unmarshal([]byte(output), &keys); err != nil {
		return 0, fmt.Errorf("failed to parse API keys: %v", err)
	}

	for _, k := range keys {
		if k.Prefix == prefix {
			expiresAt := time.Unix(k.Expiration.Seconds, 0)
			return time.Until(expiresAt), nil
		}
	}

	return 0, fmt.Errorf("key not found in headscale")
}

// dockerExec runs a command in a container via Docker API
func dockerExec(container string, cmd []string) (string, error) {
	client := helper.NewDockerHTTPClientWithTimeout(30 * time.Second)

	// Build exec create body
	cmdJSON, _ := json.Marshal(cmd)
	execCreateBody := fmt.Sprintf(`{"AttachStdout":true,"AttachStderr":true,"Cmd":%s}`, cmdJSON)

	resp, err := client.Post(
		fmt.Sprintf("http://localhost/containers/%s/exec", container),
		"application/json",
		strings.NewReader(execCreateBody),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return "", fmt.Errorf("failed to create exec: status %d", resp.StatusCode)
	}

	var execCreate struct {
		Id string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&execCreate); err != nil {
		return "", fmt.Errorf("failed to parse exec response: %v", err)
	}

	// Start exec
	resp2, err := client.Post(
		fmt.Sprintf("http://localhost/exec/%s/start", execCreate.Id),
		"application/json",
		strings.NewReader(`{"Detach":false,"Tty":false}`),
	)
	if err != nil {
		return "", fmt.Errorf("failed to start exec: %v", err)
	}
	defer resp2.Body.Close()

	return demuxDockerStream(resp2.Body)
}

// GetStatus returns the current setup status
func (s *Service) GetStatus() (*SetupStatus, error) {
	status := &SetupStatus{}

	// Check if admin user exists
	if s.auth != nil {
		status.HasAdmin = s.auth.HasUsers()
	}

	// Check if headscale is configured (check for api_url which is the internal one)
	_, err := settings.GetSetting("headscale_api_url")
	status.HasHeadscale = err == nil

	// Check if adguard password has been changed
	_, err = settings.GetSetting("adguard_pass_changed")
	status.AdguardPassChanged = err == nil

	// Setup is complete if we have admin and headscale
	status.Completed = status.HasAdmin && status.HasHeadscale

	return status, nil
}

// CompleteSetup runs the initial setup
func (s *Service) CompleteSetup(req *SetupRequest) error {
	// Validate required fields
	if req.AdminUsername == "" || req.AdminPassword == "" {
		return fmt.Errorf("admin username and password are required")
	}
	if req.HeadscaleAPIURL == "" || req.HeadscaleAPIKey == "" {
		return fmt.Errorf("headscale API URL and API key are required")
	}
	if req.HeadscaleURL == "" {
		return fmt.Errorf("headscale public URL is required")
	}

	// Create admin user (if not exists)
	if s.auth != nil && !s.auth.HasUsers() {
		_, err := s.auth.CreateUser(req.AdminUsername, req.AdminPassword)
		if err != nil {
			return fmt.Errorf("failed to create admin user: %v", err)
		}
		log.Printf("Created admin user: %s", req.AdminUsername)
	}

	// Store headscale settings (encrypted)
	if err := settings.SetSettingEncrypted("headscale_api_key", req.HeadscaleAPIKey); err != nil {
		return fmt.Errorf("failed to store headscale API key: %v", err)
	}

	// Store internal API URL
	if err := settings.SetSetting("headscale_api_url", req.HeadscaleAPIURL); err != nil {
		return fmt.Errorf("failed to store headscale API URL: %v", err)
	}

	// Store public URL for Tailscale clients
	if err := settings.SetSetting("headscale_url", req.HeadscaleURL); err != nil {
		return fmt.Errorf("failed to store headscale URL: %v", err)
	}

	// Clean up pending key if exists
	_ = settings.DeleteSetting("headscale_api_key_pending")

	log.Printf("Setup completed successfully")
	return nil
}

// HTTP Handlers

func (s *Service) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.GetStatus()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, status)
}

func (s *Service) handleCompleteSetup(w http.ResponseWriter, r *http.Request) {
	// Lock to prevent race condition with concurrent setup attempts
	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	// Check if already setup (inside lock to prevent TOCTOU race)
	status, _ := s.GetStatus()
	if status.Completed {
		router.JSONError(w, "Setup already completed", http.StatusBadRequest)
		return
	}

	var req SetupRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if err := s.CompleteSetup(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	router.JSON(w, map[string]string{"message": "Setup completed"})
}

// TestHeadscaleRequest for testing headscale connection
type TestHeadscaleRequest struct {
	URL    string `json:"url"`
	APIKey string `json:"apiKey"`
}

func (s *Service) handleTestHeadscale(w http.ResponseWriter, r *http.Request) {
	var req TestHeadscaleRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.URL == "" || req.APIKey == "" {
		router.JSONError(w, "URL and API key are required", http.StatusBadRequest)
		return
	}

	// Validate and sanitize URL to prevent SSRF
	sanitizedURL, err := helper.SanitizeInternalServiceURL(req.URL)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Ensure URL has /api/v1 suffix
	baseURL := sanitizedURL
	if !strings.HasSuffix(baseURL, "/api/v1") {
		baseURL = strings.TrimSuffix(baseURL, "/") + "/api/v1"
	}
	testURL := baseURL + "/user"

	// Test connection to headscale
	client := &http.Client{Timeout: helper.HTTPClientTimeout}
	testReq, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		router.JSONError(w, "Invalid URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	testReq.Header.Set("Authorization", "Bearer "+req.APIKey)

	resp, err := client.Do(testReq)
	if err != nil {
		router.JSONError(w, "Connection failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		router.JSONError(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	if resp.StatusCode >= 400 {
		router.JSONError(w, fmt.Sprintf("Headscale returned error: %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	router.JSON(w, map[string]string{"status": "ok"})
}
