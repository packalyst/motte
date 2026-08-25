// Package events is a lightweight, cross-subsystem activity log. Any subsystem
// can record a notable action (a block, a peer change, a config edit) with a
// single best-effort Log call; the panel surfaces them as one chronological
// feed. Recording is never allowed to break the caller's operation.
package events

import (
	"log"
	"strings"
	"sync/atomic"

	"api/internal/database"
)

// Severity levels.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// maxRows caps retained events so the table cannot grow without bound. Old rows
// are trimmed periodically (see trimEvery) rather than on every insert.
const (
	maxRows   = 2000
	trimEvery = 100
)

// insertCount drives periodic trimming without a lock on the hot path.
var insertCount atomic.Uint64

// Event is a single activity-feed entry.
type Event struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Subsystem string `json:"subsystem"`
	Message   string `json:"message"`
}

// Log records an activity event. It is best-effort: any error is logged and
// swallowed so a failed insert never affects the operation that triggered it.
func Log(subsystem, eventType, severity, message string) {
	if severity == "" {
		severity = SeverityInfo
	}
	db, err := database.GetDB()
	if err != nil {
		return
	}
	res, err := db.Exec(
		`INSERT INTO events (type, severity, subsystem, message) VALUES (?, ?, ?, ?)`,
		eventType, severity, subsystem, message,
	)
	if err != nil {
		log.Printf("events: failed to record %s/%s: %v", subsystem, eventType, err)
		return
	}
	// Trim occasionally to bound the table.
	if insertCount.Add(1)%trimEvery == 0 {
		if id, err := res.LastInsertId(); err == nil {
			trim(db, id)
		}
	}
}

// trim deletes rows older than the most recent maxRows.
func trim(db *database.DB, latestID int64) {
	cutoff := latestID - maxRows
	if cutoff <= 0 {
		return
	}
	if _, err := db.Exec(`DELETE FROM events WHERE id <= ?`, cutoff); err != nil {
		log.Printf("events: trim failed: %v", err)
	}
}

// List returns the most recent events, newest first. limit is clamped to a sane
// range; typeFilter and subsystemFilter, when non-empty, restrict the result. Both
// are applied in SQL so a low-volume subsystem isn't missed just because it fell
// outside the newest `limit` rows across all subsystems.
func List(limit int, typeFilter, subsystemFilter string) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}

	// Emit created_at as ISO-8601 UTC (…Z) so the browser parses it as UTC
	// rather than local time — SQLite's default "YYYY-MM-DD HH:MM:SS" is
	// zone-ambiguous and would skew "time ago".
	const cols = `id, strftime('%Y-%m-%dT%H:%M:%SZ', created_at) AS created_at, type, severity, subsystem, message`
	conds := []string{}
	args := []interface{}{}
	if typeFilter != "" {
		conds = append(conds, "type = ?")
		args = append(args, typeFilter)
	}
	if subsystemFilter != "" {
		conds = append(conds, "subsystem = ?")
		args = append(args, subsystemFilter)
	}
	q := `SELECT ` + cols + ` FROM events`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Event, 0, min(limit, 500)) // limit is already clamped to <=500; bound the prealloc locally too
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Type, &e.Severity, &e.Subsystem, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
