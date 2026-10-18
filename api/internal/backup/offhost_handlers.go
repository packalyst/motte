package backup

import (
	"context"
	"errors"
	"net/http"
	"time"

	"api/internal/auth"
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
	var incoming OffhostConfig
	if !router.DecodeJSONOrError(w, r, &incoming) {
		return
	}
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
	// Pin a newly-seen SFTP host key into the stored config so future runs verify strictly.
	if hk := be.learnedHostKey(); hk != "" && d.ID != "" {
		for i := range stored.Destinations {
			if stored.Destinations[i].ID == d.ID && stored.Destinations[i].HostKey == "" {
				stored.Destinations[i].HostKey = hk
				_ = s.saveOffhostConfig(stored)
			}
		}
	}
	router.JSON(w, map[string]interface{}{"ok": true, "existing": len(objs), "hostKey": be.learnedHostKey()})
}

func (s *Service) handleOffhostRunNow(w http.ResponseWriter, r *http.Request) {
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
	p := router.CurrentUser(r)
	if p == nil {
		router.JSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	a := auth.GetService()
	if a == nil {
		router.JSONError(w, "auth unavailable", http.StatusServiceUnavailable)
		return
	}
	// Step-up: password (+ fresh 2FA when enabled). 428 re-prompts; never 401 (would force logout).
	if err := a.VerifyStepUp(p.UserID, req.CurrentPassword, req.TotpCode); err != nil {
		msg := err.Error()
		if errors.Is(err, auth.ErrStepUpTOTPRequired) {
			msg = "two-factor authentication code required"
		}
		router.JSONWithStatus(w, map[string]interface{}{"error": msg, "stepup": true, "totp": a.TOTPEnabled(p.UserID)}, http.StatusPreconditionRequired)
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
