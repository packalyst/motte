package fleet

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"api/internal/helper"
)

// HandleReport ingests an agent's periodic report (mTLS-gated). The raw JSON is
// stored as the machine's last_report and last_seen is bumped. The machine is
// taken from the client cert, never the body — an agent can only update itself.
func (s *Service) HandleReport(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if m == nil {
		writeErr(w, http.StatusUnauthorized, "no machine")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, helper.MaxReportBytes))
	if err != nil || !json.Valid(body) {
		writeErr(w, http.StatusBadRequest, "invalid report")
		return
	}
	if body, err = s.mergePartialReport(m.ID, body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid report")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(
		`UPDATE fleet_machines SET last_report = ?, last_seen = ?, status = 'online', last_ip = ? WHERE id = ?`,
		string(body), now, helper.GetClientIP(r), m.ID,
	); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	// Fold this report's live metrics into the machine's usage history (5-min buckets).
	// Best-effort — never fail an ingest over history.
	s.recordMetrics(m.ID, body)
	// Push the fresh report to any browser watching this machine, so the UI updates live
	// instead of polling. The command log rides its own event-driven broadcasts
	// (enqueue / deliver / ack), so we don't query it on every idle check-in here.
	if s.broadcast != nil {
		s.scopedBroadcast(m.ID, "fleet", map[string]any{"machine_id": m.ID, "report": json.RawMessage(body), "last_seen": now})
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// rareSections are the report parts an agent leaves out while they're unchanged.
var rareSections = []string{"cves", "intrusion", "facts"}

// mergePartialReport fills a partial report's omitted sections from the machine's stored
// report, so last_report and the live push always carry the full picture. A report without
// the partial flag (older agents, or the periodic full one) is stored as sent.
func (s *Service) mergePartialReport(machineID string, body []byte) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, err
	}
	flag, ok := in["partial"]
	if !ok {
		return body, nil
	}
	delete(in, "partial")
	if string(flag) == "true" {
		var prev sql.NullString
		_ = s.db.QueryRow(`SELECT last_report FROM fleet_machines WHERE id = ?`, machineID).Scan(&prev)
		var old map[string]json.RawMessage
		_ = json.Unmarshal([]byte(prev.String), &old) // none stored yet: nothing to fill in
		for _, k := range rareSections {
			if _, has := in[k]; !has {
				if v, ok := old[k]; ok {
					in[k] = v
				}
			}
		}
	}
	return json.Marshal(in)
}
