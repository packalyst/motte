package events

import (
	"net/http"
	"strconv"

	"api/internal/router"
)

// Service exposes the activity feed over HTTP. It is stateless — events are
// recorded via the package-level Log from anywhere.
type Service struct{}

// New creates the events service.
func New() *Service { return &Service{} }

// Handlers registers the events endpoints.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"ListEvents": s.handleList,
	}
}

// handleList returns the recent activity feed: GET /api/events?limit=&type=
func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	typeFilter := r.URL.Query().Get("type")

	list, err := List(limit, typeFilter)
	if err != nil {
		router.JSONError(w, "failed to load events", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"events": list})
}
