// Package events is a lightweight, cross-subsystem activity log. Any subsystem
// can record a notable action (a block, a peer change, a config edit) with a
// single best-effort Log call; the panel surfaces them as one chronological
// feed. Recording is never allowed to break the caller's operation.
//
// The same feed doubles as the audit trail: security-relevant actions are
// recorded with Audit, which attributes the event to an actor (who) and a source
// IP (from where). Audit rows are exempt from the operational retention cap so a
// flood of routine activity can never evict the security trail.
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

// maxRows caps retained operational (non-audit) events so the table cannot grow
// without bound. Audit rows — those attributed to an actor — are exempt from this
// cap and kept up to maxAuditRows instead, a far-off backstop a low-volume panel
// effectively never reaches, so routine activity can't evict the security trail.
// Old rows are trimmed periodically (see trimEvery) rather than on every insert.
const (
	maxRows      = 2000
	maxAuditRows = 50000
	trimEvery    = 100
)

// insertCount drives periodic trimming without a lock on the hot path.
var insertCount atomic.Uint64

// Event is a single activity-feed entry. Actor and IP are set only on audit
// entries (recorded via Audit); operational entries leave them empty.
type Event struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Subsystem string `json:"subsystem"`
	Message   string `json:"message"`
	Actor     string `json:"actor,omitempty"`
	IP        string `json:"ip,omitempty"`
}

// Log records an operational activity event (no actor/IP). It is best-effort: any
// error is logged and swallowed so a failed insert never affects the operation
// that triggered it.
func Log(subsystem, eventType, severity, message string) {
	insert(subsystem, eventType, severity, "", "", message)
}

// Audit records a security-relevant event attributed to an actor (the acting
// username, or the claimed one on a failed attempt) and a source IP. Audit rows
// are retained far longer than operational rows (see trim). Like Log it is
// best-effort and never breaks the caller's operation.
func Audit(subsystem, eventType, severity, actor, ip, message string) {
	insert(subsystem, eventType, severity, actor, ip, message)
}

// insert is the shared write path for Log and Audit.
func insert(subsystem, eventType, severity, actor, ip, message string) {
	if severity == "" {
		severity = SeverityInfo
	}
	db, err := database.GetDB()
	if err != nil {
		return
	}
	res, err := db.Exec(
		`INSERT INTO events (type, severity, subsystem, message, actor, ip) VALUES (?, ?, ?, ?, ?, ?)`,
		eventType, severity, subsystem, message, actor, ip,
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

// trim bounds the table without touching the security trail. Operational rows
// (no actor) are capped at the newest maxRows; audit rows (actor set) are exempt
// from that cap and bounded separately at the far-off maxAuditRows backstop, so a
// burst of routine activity can never evict audit records.
func trim(db *database.DB, latestID int64) {
	if cutoff := latestID - maxRows; cutoff > 0 {
		if _, err := db.Exec(
			`DELETE FROM events WHERE id <= ? AND (actor IS NULL OR actor = '')`, cutoff,
		); err != nil {
			log.Printf("events: trim failed: %v", err)
		}
	}
	if _, err := db.Exec(
		`DELETE FROM events WHERE actor IS NOT NULL AND actor != '' AND id NOT IN (
			SELECT id FROM events WHERE actor IS NOT NULL AND actor != '' ORDER BY id DESC LIMIT ?
		)`, maxAuditRows,
	); err != nil {
		log.Printf("events: audit trim failed: %v", err)
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
	const cols = `id, strftime('%Y-%m-%dT%H:%M:%SZ', created_at) AS created_at, type, severity, subsystem, message, COALESCE(actor, '') AS actor, COALESCE(ip, '') AS ip`
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

	// Don't size the prealloc from `limit` (a request value) — grow on append instead, so
	// the allocation size is input-independent. `limit` is capped at 500 in List() anyway,
	// so at most 500 small structs are appended.
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Type, &e.Severity, &e.Subsystem, &e.Message, &e.Actor, &e.IP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
