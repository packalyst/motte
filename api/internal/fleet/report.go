package fleet

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

const maxReportBody = 1 << 20 // 1 MiB

// HandleReport ingests an agent's periodic report (mTLS-gated). The raw JSON is
// stored as the machine's last_report and last_seen is bumped. The machine is
// taken from the client cert, never the body — an agent can only update itself.
func (s *Service) HandleReport(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if m == nil {
		writeErr(w, http.StatusUnauthorized, "no machine")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReportBody))
	if err != nil || !json.Valid(body) {
		writeErr(w, http.StatusBadRequest, "invalid report")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(
		`UPDATE fleet_machines SET last_report = ?, last_seen = ?, status = 'online' WHERE id = ?`,
		string(body), now, m.ID,
	); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	// Push the fresh report to any browser watching this machine, so the UI updates live
	// instead of polling. Payload carries the machine id, the raw report JSON, and the
	// command log (deliver/ack happen on this same check-in), so the detail page never
	// has to poll for commands either.
	if s.broadcast != nil {
		payload := map[string]any{"machine_id": m.ID, "report": json.RawMessage(body)}
		if cmds, err := s.ListMachineCommands(m.ID, 20); err == nil {
			payload["commands"] = cmds
		}
		s.broadcast("fleet", payload)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
