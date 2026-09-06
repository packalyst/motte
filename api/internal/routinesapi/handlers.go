// Package routinesapi is the thin HTTP layer over the routines supervisor. It is
// separate from the routines core so that core can stay a leaf package (no
// router import) and be registered from anywhere without an import cycle.
package routinesapi

import (
	"net/http"

	"api/internal/router"
	"api/internal/routines"
)

// Service exposes the routines endpoints as a router service.
type Service struct{}

// New returns the routines HTTP service.
func New() *Service { return &Service{} }

// Handlers maps endpoints.json handler names to funcs.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"List":   s.handleList,
		"Run":    s.handleRun,
		"Pause":  s.handlePause,
		"Resume": s.handleResume,
	}
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]interface{}{"routines": routines.List()})
}

func (s *Service) handleRun(w http.ResponseWriter, r *http.Request) {
	s.control(w, r, routines.RunNow, "triggered")
}

func (s *Service) handlePause(w http.ResponseWriter, r *http.Request) {
	s.control(w, r, routines.Pause, "paused")
}

func (s *Service) handleResume(w http.ResponseWriter, r *http.Request) {
	s.control(w, r, routines.Resume, "resumed")
}

// control extracts the {name} path param, applies the action, and replies —
// shared by run/pause/resume so the three handlers don't duplicate the plumbing.
func (s *Service) control(w http.ResponseWriter, r *http.Request, action func(string) bool, ok string) {
	name := router.ExtractPathParam(r, "/api/routines/")
	if name == "" {
		router.JSONError(w, "routine name required", http.StatusBadRequest)
		return
	}
	if !action(name) {
		router.JSONError(w, "unknown routine: "+name, http.StatusNotFound)
		return
	}
	router.JSON(w, map[string]string{"status": ok, "routine": name})
}
