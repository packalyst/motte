package events

import (
	"net/http"
	"strconv"
	"strings"

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

// maxSearch bounds the search text (it becomes a LIKE pattern over every retained row).
const maxSearch = 100

// handleList returns the activity feed: GET /api/events?limit=&type=&subsystem=&severity=&q=&before=&facets=1
// The response carries `next` (pass it as before= for older events) while more may exist, and
// with facets=1 the subsystems that have events, for the filter.
func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q := Query{
		Type:      v.Get("type"),
		Subsystem: v.Get("subsystem"),
		Search:    strings.TrimSpace(v.Get("q")),
	}
	n, _ := strconv.Atoi(v.Get("limit"))
	q.Limit = pageSize(n)
	switch sev := v.Get("severity"); sev {
	case "", SeverityInfo, SeverityWarning, SeverityCritical:
		q.Severity = sev
	default:
		router.JSONError(w, "invalid severity", http.StatusBadRequest)
		return
	}
	if len(q.Search) > maxSearch {
		router.JSONError(w, "search is too long", http.StatusBadRequest)
		return
	}
	if b := v.Get("before"); b != "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n <= 0 {
			router.JSONError(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		q.Before = n
	}

	list, err := List(q)
	if err != nil {
		router.JSONError(w, "failed to load events", http.StatusInternalServerError)
		return
	}
	out := map[string]any{"events": list}
	if len(list) == q.Limit {
		out["next"] = list[len(list)-1].ID
	}
	if v.Get("facets") == "1" {
		sources, err := Sources()
		if err != nil {
			router.JSONError(w, "failed to load events", http.StatusInternalServerError)
			return
		}
		out["sources"] = sources
	}
	router.JSON(w, out)
}
