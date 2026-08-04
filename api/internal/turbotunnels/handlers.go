package turbotunnels

import (
	"log"
	"net/http"

	"api/internal/router"
)

// Service exposes turbotunnels lifecycle + config handlers to the router.
type Service struct{}

// New creates a new turbotunnels service.
func New() *Service {
	return &Service{}
}

// Handlers returns the handler map for the router.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetStatus":      s.handleStatus,
		"GetStats":       s.handleStats,
		"TestTunnel":     s.handleTest,
		"GetConfig":      s.handleGetConfig,
		"SaveConfig":     s.handleSaveConfig,
		"GenCredentials": s.handleGenCredentials,
		"QuickDeploy":    s.handleQuickDeploy,
		"Start":          s.handleStart,
		"Stop":           s.handleStop,
		"Restart":        s.handleRestart,
	}
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, GetStatus())
}

// handleStats returns proxy usage (overall + per tunnel) for the last 24h.
func (s *Service) handleStats(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, GetProxyStats())
}

// handleTest probes a tunnel end-to-end (through the proxy) and reports up/down
// + exit IP. The tunnel must be running to pass.
func (s *Service) handleTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Pass     string `json:"pass"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	router.JSON(w, TestTunnel(req.Protocol, req.Port, req.User, req.Pass))
}

// handleGetConfig returns the saved tunnel configuration for the editor.
func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := LoadConfig()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, cfg)
}

// handleSaveConfig validates and persists the configuration. It does NOT
// restart the container — the UI asks the user to restart to apply, and the
// status drift flag reflects the pending change.
func (s *Service) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	if !router.DecodeJSONOrError(w, r, &cfg) {
		return
	}
	// Assign IDs to any new tunnels so the UI has a stable key.
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].ID == "" {
			cfg.Tunnels[i].ID = newTunnelID()
		}
	}
	if err := SaveConfig(cfg); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	router.JSON(w, GetStatus())
}

// handleGenCredentials returns a fresh strong username/password pair for the
// "regenerate credentials" button. Nothing is persisted until the config is
// saved.
func (s *Service) handleGenCredentials(w http.ResponseWriter, r *http.Request) {
	user, pass := GenCredentials()
	router.JSON(w, map[string]string{"user": user, "pass": pass})
}

// handleQuickDeploy is the one-click "direct proxy on this server" path: if no
// tunnels exist yet it creates a single direct tunnel with auto-generated
// credentials on the first free port, then starts the container.
func (s *Service) handleQuickDeploy(w http.ResponseWriter, r *http.Request) {
	cfg, err := LoadConfig()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(cfg.Tunnels) == 0 {
		user, pass := GenCredentials()
		cfg.Tunnels = []Tunnel{{
			ID:        newTunnelID(),
			Name:      "Quick proxy",
			Listeners: []Listener{{Protocol: "http", Port: firstFreePort(3128)}},
			User:      user,
			Pass:      pass,
		}}
		if err := SaveConfig(cfg); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := Start(); err != nil {
		log.Printf("turbotunnels quick-deploy start error: %v", err)
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, GetStatus())
}

func (s *Service) handleStart(w http.ResponseWriter, r *http.Request) {
	if err := Start(); err != nil {
		log.Printf("turbotunnels start error: %v", err)
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, GetStatus())
}

func (s *Service) handleStop(w http.ResponseWriter, r *http.Request) {
	if err := Stop(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, GetStatus())
}

func (s *Service) handleRestart(w http.ResponseWriter, r *http.Request) {
	if err := Restart(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, GetStatus())
}
