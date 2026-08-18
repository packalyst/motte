package fleet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"api/internal/router"
)

// Admin handlers run on the panel's NORMAL authenticated API router (not the
// fleet mTLS listener). They let the operator mint enrollment tokens and view the
// fleet. Registered as the "fleet" service in endpoints.json.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"CreateToken":    s.handleCreateToken,
		"ListMachines":   s.handleListMachines,
		"CAInfo":         s.handleCAInfo,
		"EnqueueCommand": s.handleEnqueueCommand,
		"MachineReport":  s.handleMachineReport,
		"FleetEndpoints": s.handleEndpoints,
		"SetConfig":      s.handleSetConfig,
	}
}

// handleSetConfig turns the fleet listener on/off and sets its port, then applies
// it live (starts/stops the mTLS listener + opens/closes the firewall port). This
// is the "flip a switch" control — no env vars.
// POST /api/fleet/config  {"enabled":true,"port":9443}
func (s *Service) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		Port    int  `json:"port"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		router.JSONError(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Port == 0 {
		req.Port = defaultPort
	}
	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "port out of range", http.StatusBadRequest)
		return
	}
	if err := s.setSetting(settingEnabled, boolStr(req.Enabled)); err != nil {
		router.JSONError(w, "save failed", http.StatusInternalServerError)
		return
	}
	if err := s.setSetting(settingPort, fmt.Sprintf("%d", req.Port)); err != nil {
		router.JSONError(w, "save failed", http.StatusInternalServerError)
		return
	}
	s.ReloadFromSettings()
	enabled, port := s.Status()
	router.JSON(w, map[string]any{"enabled": enabled, "port": s.effectivePort(), "listening": enabled})
	_ = port
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

type createTokenRequest struct {
	Label      string `json:"label"`
	TTLSeconds int    `json:"ttl_seconds"`
	PanelHost  string `json:"panel_host"` // address the agent will dial (WG IP / public IP / domain)
}

// handleEndpoints tells the UI the fleet state + the addresses agents can reach the
// panel on, so the Add-Machine dialog can offer WG vs public without env vars.
func (s *Service) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	enabled, port := s.Status()
	router.JSON(w, map[string]any{
		"enabled":     enabled,
		"port":        s.effectivePort(),
		"listening":   enabled,
		"hosts":       s.HostCandidates(),
		"fingerprint": s.ca.Fingerprint(),
	})
	_ = port
}

func (s *Service) effectivePort() int {
	if _, p := s.Status(); p != 0 {
		return p
	}
	if v := s.getSetting(settingPort); v != "" {
		if p, err := parsePort(v); err == nil {
			return p
		}
	}
	return defaultPort
}

type createTokenResponse struct {
	Token          string    `json:"token"`
	Label          string    `json:"label"`
	ExpiresAt      time.Time `json:"expires_at"`
	CAFingerprint  string    `json:"ca_fingerprint"`
	PanelURL       string    `json:"panel_url"`
	InstallCommand string    `json:"install_command"`
}

// handleCreateToken mints a one-time enrollment token. The plaintext is returned
// ONCE here (the UI shows it inside the install command) and never again.
func (s *Service) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req)
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	tok, err := s.CreateToken(req.Label, ttl)
	if err != nil {
		router.JSONError(w, "could not create token", http.StatusInternalServerError)
		return
	}
	host := strings.TrimSpace(req.PanelHost)
	if host == "" {
		if c := s.HostCandidates(); len(c) > 0 {
			host = c[0]
		}
	}
	panelURL, install := "", ""
	if host != "" {
		panelURL = fmt.Sprintf("https://%s:%d", host, s.effectivePort())
		install = fmt.Sprintf("curl -fsSL %s | sudo sh -s -- --panel %s --ca-fp %s --token %s",
			s.installURL, panelURL, s.ca.Fingerprint(), tok.Plaintext)
	}
	router.JSON(w, createTokenResponse{
		Token:          tok.Plaintext,
		Label:          tok.Label,
		ExpiresAt:      tok.ExpiresAt,
		CAFingerprint:  s.ca.Fingerprint(),
		PanelURL:       panelURL,
		InstallCommand: install,
	})
}

func (s *Service) handleListMachines(w http.ResponseWriter, r *http.Request) {
	ms, err := s.ListMachines()
	if err != nil {
		router.JSONError(w, "could not list machines", http.StatusInternalServerError)
		return
	}
	router.JSON(w, ms)
}

// handleCAInfo returns the CA fingerprint + PEM (for building install commands).
func (s *Service) handleCAInfo(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{
		"fingerprint": s.ca.Fingerprint(),
		"cert_pem":    string(s.ca.CertPEM()),
	})
}

// handleEnqueueCommand queues an allowlisted command for a machine.
// POST /api/fleet/command  {"machine_id":"...","type":"block","payload":{"ip":"1.2.3.4"}}
func (s *Service) handleEnqueueCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID string          `json:"machine_id"`
		Type      string          `json:"type"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		router.JSONError(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.MachineID == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	id, err := s.Enqueue(req.MachineID, req.Type, req.Payload)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	router.JSON(w, map[string]string{"command_id": id})
}

// handleMachineReport returns a machine's latest report JSON.
// GET /api/fleet/report?id=<machine_id>
func (s *Service) handleMachineReport(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		router.JSONError(w, "id required", http.StatusBadRequest)
		return
	}
	raw, err := s.lastReport(id)
	if err != nil {
		router.JSONError(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if raw == "" {
		raw = "null"
	}
	_, _ = w.Write([]byte(raw))
}
