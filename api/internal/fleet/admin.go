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
		"CreateToken":     s.handleCreateToken,
		"ListMachines":    s.handleListMachines,
		"CAInfo":          s.handleCAInfo,
		"EnqueueCommand":  s.handleEnqueueCommand,
		"MachineReport":   s.handleMachineReport,
		"FleetEndpoints":  s.handleEndpoints,
		"SetConfig":       s.handleSetConfig,
		"PushBlocks":      s.handlePushBlocks,
		"DeleteMachine":   s.handleDeleteMachine,
		"CVEGroups":       s.handleCVEGroups,
		"ListCVEs":        s.handleListCVEs,
		"ExportCVEs":      s.handleExportCVEs,
		"FixPackages":     s.handleFixPackages,
		"MachineCommands": s.handleMachineCommands,
	}
}

// handleDeleteMachine removes a machine and everything tied to it (registry row +
// queued commands), which invalidates its client cert. To return, the host must
// re-enroll with a fresh one-time token.
// POST /api/fleet/machine/delete  {"machine_id":"..."}
func (s *Service) handleDeleteMachine(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID string `json:"machine_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil || req.MachineID == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	if err := s.DeleteMachine(req.MachineID); err != nil {
		router.JSONError(w, "machine not found", http.StatusNotFound)
		return
	}
	router.JSON(w, map[string]bool{"ok": true})
}

// handlePushBlocks queues a sync-blocks command carrying the panel's current explicit
// blocklist (operator + escalation ip/range entries) so the machine blocks them too.
// POST /api/fleet/push-blocks  {"machine_id":"..."}
func (s *Service) handlePushBlocks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID string `json:"machine_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil || req.MachineID == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	if s.blockedIPs == nil {
		router.JSONError(w, "blocklist unavailable", http.StatusServiceUnavailable)
		return
	}
	ips := s.blockedIPs()
	// Cap defensively so a runaway blocklist can't build a giant nft set on the host.
	const maxPush = 5000
	if len(ips) > maxPush {
		ips = ips[:maxPush]
	}
	payload, _ := json.Marshal(map[string]any{"ips": ips})
	id, err := s.Enqueue(req.MachineID, "sync-blocks", payload)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	router.JSON(w, map[string]any{"command_id": id, "count": len(ips)})
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
	PanelHost  string `json:"panel_host"` // direct origin the agent dials for mTLS (IP the operator picked)
}

// handleEndpoints tells the UI the fleet state + the addresses agents can reach the
// panel on, so the Add-Machine dialog can offer WG vs public without env vars.
func (s *Service) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	enabled, _ := s.Status()
	router.JSON(w, map[string]any{
		"enabled":     enabled,
		"port":        s.effectivePort(),
		"listening":   enabled,
		"domain":      s.sslDomain,        // download domain the install command uses (empty ⇒ none)
		"hosts":       s.HostCandidates(), // addresses the agent could dial for mTLS (operator picks)
		"fingerprint": s.ca.Fingerprint(),
	})
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
	// The agent's mTLS channel dials the direct origin the operator picked (an IP);
	// recorded with the token so the install endpoint bakes it into --panel. Default to
	// the first public IP if none was picked.
	panelHost := strings.TrimSpace(req.PanelHost)
	if panelHost == "" {
		panelHost = firstPublicIP()
	}
	tok, err := s.CreateToken(req.Label, ttl, panelHost)
	if err != nil {
		router.JSONError(w, "could not create token", http.StatusInternalServerError)
		return
	}
	// The installer is DOWNLOADED over the panel domain via Traefik/443 (real cert → the
	// command needs no CA handling); the agent then talks mTLS to panelHost:port.
	// Without a domain there's no trusted public cert, so no one-command install is
	// offered (the UI tells the operator to set a domain).
	panelURL, install := "", ""
	if s.sslDomain != "" {
		panelURL = fmt.Sprintf("https://%s:%d", panelHost, s.effectivePort())
		install = fmt.Sprintf(`curl -fsSL "https://%s/agent/%s?arch=$(uname -m)" | sudo sh`, s.sslDomain, tok.Plaintext)
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
