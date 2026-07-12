package turbotunnels

import (
	"log"
	"net/http"

	"api/internal/router"
)

// Service exposes turbotunnels lifecycle handlers to the router.
type Service struct{}

// New creates a new turbotunnels service.
func New() *Service {
	return &Service{}
}

// Handlers returns the handler map for the router.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetStatus": s.handleStatus,
		"Start":     s.handleStart,
		"Stop":      s.handleStop,
		"Restart":   s.handleRestart,
	}
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, GetStatus())
}

func (s *Service) handleStart(w http.ResponseWriter, r *http.Request) {
	if err := Start(); err != nil {
		log.Printf("turbotunnels start error: %v", err)
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "running"})
}

func (s *Service) handleStop(w http.ResponseWriter, r *http.Request) {
	if err := Stop(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "stopped"})
}

func (s *Service) handleRestart(w http.ResponseWriter, r *http.Request) {
	if err := Restart(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "ok"})
}
