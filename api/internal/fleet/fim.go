package fleet

import (
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"api/internal/router"
)

// FIMEvent is one file-integrity change reported by an agent (osquery file_events).
type FIMEvent struct {
	Action string `json:"action"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Time   string `json:"time,omitempty"`
}

// HandleFIMReport (POST, mTLS) ingests a machine's FIM event tail (gzip-compressed), replacing
// the machine's stored events. Mirrors HandleCVEReport — the periodic /report only carries a
// count, so the full filterable list lives here → DB → drill-down.
func (s *Service) HandleFIMReport(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if m == nil {
		writeErr(w, http.StatusUnauthorized, "unknown machine")
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, 16<<20) // 16 MiB compressed cap
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad gzip")
			return
		}
		defer gz.Close()
		body = gz
	}
	var payload struct {
		Events []FIMEvent `json:"events"`
	}
	if err := json.NewDecoder(io.LimitReader(body, 32<<20)).Decode(&payload); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	const maxEvents = 5000
	if len(payload.Events) > maxEvents {
		payload.Events = payload.Events[len(payload.Events)-maxEvents:]
	}
	if err := s.IngestFIM(m.ID, payload.Events); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"stored": len(payload.Events)})
}

// IngestFIM replaces the machine's FIM rows with events, in one transaction.
func (s *Service) IngestFIM(machineID string, events []FIMEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM fleet_fim WHERE machine_id = ?`, machineID); err != nil {
		_ = tx.Rollback()
		return err
	}
	const batchRows = 500
	const tuple = "(?,?,?,?,?)"
	prefix := `INSERT INTO fleet_fim (machine_id, action, path, sha256, event_time) VALUES `
	args := make([]any, 0, batchRows*5)
	rows := 0
	flush := func() error {
		if rows == 0 {
			return nil
		}
		q := prefix + tuple + strings.Repeat(","+tuple, rows-1)
		_, err := tx.Exec(q, args...)
		args = args[:0]
		rows = 0
		return err
	}
	for _, e := range events {
		args = append(args, machineID, e.Action, e.Path, e.SHA256, e.Time)
		rows++
		if rows >= batchRows {
			if err := flush(); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	if err := flush(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// handleFIM (GET /api/fleet/fim?machine_id=&limit=&offset=) returns a machine's FIM events,
// most recent first, plus the total — for the Security-events drill-down modal.
func (s *Service) handleFIM(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("machine_id")
	if id == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	var total int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM fleet_fim WHERE machine_id = ?`, id).Scan(&total)
	rows, err := s.db.Query(`SELECT action, path, sha256, event_time FROM fleet_fim
		WHERE machine_id = ? ORDER BY event_time DESC, rowid DESC LIMIT ? OFFSET ?`, id, limit, offset)
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []FIMEvent{}
	for rows.Next() {
		var e FIMEvent
		var sha, t sql.NullString
		if err := rows.Scan(&e.Action, &e.Path, &sha, &t); err == nil {
			e.SHA256, e.Time = sha.String, t.String
			out = append(out, e)
		}
	}
	router.JSON(w, map[string]any{"events": out, "total": total})
}
