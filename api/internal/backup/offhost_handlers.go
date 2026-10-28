package backup

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

func (s *Service) handleOffhostGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadOffhostConfig()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, cfg.masked())
}

func (s *Service) handleOffhostSaveConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OffhostConfig
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &body) {
		return
	}
	// Owner + step-up: this config sets the passphrase, destination and include-users that a
	// scheduled full export (decrypted secrets) will use.
	if _, ok := requireStepUp(w, r, body.CurrentPassword, body.TotpCode); !ok {
		return
	}
	incoming := body.OffhostConfig
	stored, err := s.loadOffhostConfig()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := mergeSecrets(incoming, stored)
	if cfg.Hour < 0 || cfg.Hour > 23 {
		cfg.Hour = 3
	}
	if cfg.KeepN < 0 {
		cfg.KeepN = 0
	}
	// Only block the save when turning scheduling ON with an invalid config; allow partial drafts.
	if cfg.Enabled {
		if err := cfg.validate(); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := s.saveOffhostConfig(cfg); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("backup", "offhost_config_changed", events.SeverityInfo, actorOf(r), helper.GetClientIP(r),
		"Off-host backup configuration updated")
	router.JSON(w, cfg.masked())
}

func (s *Service) handleOffhostTest(w http.ResponseWriter, r *http.Request) {
	var d Destination
	if !router.DecodeJSONOrError(w, r, &d) {
		return
	}
	stored, _ := s.loadOffhostConfig()
	if prev, ok := findDest(stored, d.ID); ok {
		d = mergeDestinationSecretsFrom(d, prev)
	}
	be, err := newBackend(d)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer be.close()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	objs, err := be.list(ctx)
	if err != nil {
		router.JSONError(w, "could not reach destination: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Pin a newly-seen SFTP host key into the stored config so future runs verify strictly — only
	// when the tested server is the saved one (a test of an edited, unsaved host must not pin its key).
	if hk := be.learnedHostKey(); hk != "" && d.ID != "" {
		for i := range stored.Destinations {
			if stored.Destinations[i].ID == d.ID && stored.Destinations[i].HostKey == "" && sameSSHServer(stored.Destinations[i], d) {
				stored.Destinations[i].HostKey = hk
				_ = s.saveOffhostConfig(stored)
			}
		}
	}
	router.JSON(w, map[string]interface{}{"ok": true, "existing": len(objs), "hostKey": be.learnedHostKey()})
}

func (s *Service) handleOffhostRunNow(w http.ResponseWriter, r *http.Request) {
	// Owner + step-up: a run is a full export of decrypted secrets to the destination.
	var creds struct {
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&creds)
	if _, ok := requireStepUp(w, r, creds.CurrentPassword, creds.TotpCode); !ok {
		return
	}
	if s.Status().Running {
		router.JSONError(w, "a backup is already running", http.StatusConflict)
		return
	}
	actor := actorOf(r)
	go func() { _ = s.runOffhost(context.Background(), actor) }()
	router.JSONWithStatus(w, map[string]bool{"started": true}, http.StatusAccepted)
}

func (s *Service) handleOffhostList(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("dest")
	cfg, err := s.loadOffhostConfig()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d, ok := findDest(cfg, id)
	if !ok {
		router.JSONError(w, "destination not found", http.StatusNotFound)
		return
	}
	be, err := newBackend(d)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer be.close()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	objs, err := be.list(ctx)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	router.JSON(w, objs)
}

func (s *Service) handleOffhostStatus(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, s.Status())
}

// handleOffhostRestore pulls a chosen archive and applies it (Open+Import+Reconcile). It overwrites
// state, so it requires step-up re-authentication.
func (s *Service) handleOffhostRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Dest            string `json:"dest"`
		Name            string `json:"name"`
		Passphrase      string `json:"passphrase"` // optional override of the stored passphrase
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	p, ok := requireStepUp(w, r, req.CurrentPassword, req.TotpCode)
	if !ok {
		return
	}

	reconciled, err := s.restoreFromOffhost(r.Context(), req.Dest, req.Name, req.Passphrase)
	if err != nil {
		events.Audit("backup", "offhost_restore_failed", events.SeverityWarning, p.Username, helper.GetClientIP(r),
			"Off-host restore of "+req.Name+" failed: "+err.Error())
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	events.Audit("backup", "offhost_restored", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		"Off-host restore of "+req.Name+" applied")
	router.JSON(w, map[string]interface{}{"ok": true, "reconciled": reconciled})
}

func actorOf(r *http.Request) string {
	if p := router.CurrentUser(r); p != nil {
		return p.Username
	}
	return ""
}
