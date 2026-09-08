package fleet

import (
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
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
	// Stream-decode with a hard element cap enforced DURING decode (not after): we stop
	// reading once we have maxEvents, so a highly-compressible flood of tiny array elements
	// — small enough to slip under the compressed cap — can't amplify into a giant in-memory
	// slice. Honest agents send <=200 events (tailFIM), so this only bites abuse.
	const maxEvents = 5000
	events, err := decodeFIMEvents(io.LimitReader(body, 8<<20), maxEvents)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.IngestFIM(m.ID, events); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"stored": len(events)})
}

// decodeFIMEvents streams {"events":[...]} and returns at most max events, stopping the moment
// the cap is hit so the decoded slice can never exceed max regardless of the input size.
func decodeFIMEvents(r io.Reader, max int) ([]FIMEvent, error) {
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errBadFIM
	}
	events := []FIMEvent{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if key != "events" {
			var skip json.RawMessage // bounded by the caller's LimitReader
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}
			continue
		}
		if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
			return nil, errBadFIM
		}
		for dec.More() {
			if len(events) >= max {
				return events, nil // cap reached — ignore the rest of the stream
			}
			var e FIMEvent
			if err := dec.Decode(&e); err != nil {
				return nil, err
			}
			events = append(events, e)
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return nil, err
		}
	}
	return events, nil
}

var errBadFIM = errors.New("malformed fim payload")

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
