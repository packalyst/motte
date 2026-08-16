package firewall

import (
	"encoding/json"
	"net/http"
	"sync"
)

// L7 (Traefik/sentinel) block accounting. The sentinel plugin silent-drops requests
// whose real client IP is on the firewall block list, which leaves no trace in the
// access log. The plugin instead POSTs a periodic best-effort count here so the panel
// can show an "L7 blocked" number in the blocked-by-layer view.

var l7TableOnce sync.Once

func (s *Service) ensureL7Table() {
	l7TableOnce.Do(func() {
		s.db.Exec(`CREATE TABLE IF NOT EXISTS l7_block_samples (
			ts    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			count INTEGER NOT NULL
		)`)
		s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_l7_block_ts ON l7_block_samples(ts)`)
	})
}

// HandleInternalL7Block records a batch of sentinel block counts. Internal-only: it
// refuses any request carrying proxy/edge headers, the same guard the blocklist
// endpoint uses — only a direct call over the internal network is accepted.
func (s *Service) HandleInternalL7Block(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("CF-Connecting-IP") != "" ||
		r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Real-IP") != "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.ensureL7Table()
	var body struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Count <= 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.db.Exec(`INSERT INTO l7_block_samples (count) VALUES (?)`, body.Count)
	// Bound growth — these are rollup rows, only recent windows are ever queried.
	s.db.Exec(`DELETE FROM l7_block_samples WHERE ts < datetime('now','-60 days')`)
	w.WriteHeader(http.StatusNoContent)
}

// L7BlockedWindow returns the total number of L7 (proxy) blocks within a SQLite
// datetime interval such as "-1 hour" or "-1 day".
func (s *Service) L7BlockedWindow(interval string) int {
	s.ensureL7Table()
	var n int
	s.db.QueryRow(`SELECT COALESCE(SUM(count),0) FROM l7_block_samples
		WHERE ts > datetime('now', ?)`, interval).Scan(&n)
	return n
}
