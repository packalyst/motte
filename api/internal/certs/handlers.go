package certs

import (
	"log"
	"net/http"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"Overview":      s.handleOverview,
		"RenewListener": s.handleRenewListener,
	}
}

// GET /api/certs
func (s *Service) handleOverview(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, s.Overview(r.Context()))
}

// POST /api/certs/listener/renew replaces the agent listener's certificate now.
func (s *Service) handleRenewListener(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil || !s.fleet.ListenerEnabled() {
		router.JSONError(w, "The agent listener is off", http.StatusConflict)
		return
	}
	if err := s.fleet.RenewListenerCert(); err != nil {
		log.Printf("certs: renewing the listener certificate: %v", err)
		router.JSONError(w, "Couldn't renew the certificate; the current one is still in use", http.StatusInternalServerError)
		return
	}
	actor := ""
	if p := router.CurrentUser(r); p != nil {
		actor = p.Username
	}
	events.Audit("certs", "listener_cert_renewed", events.SeverityInfo, actor, helper.GetClientIP(r), "Agent listener certificate renewed by hand")
	router.JSON(w, s.Overview(r.Context()))
}
