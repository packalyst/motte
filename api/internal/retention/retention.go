// Package retention centralizes pruning of the aggregate rollup tables to one
// configurable window, replacing each subsystem's ad-hoc prune so retention is
// consistent and settings-driven. It touches only aggregate/counter tables — never
// raw logs or config — and every table name is a compile-time constant, so the
// DELETEs carry no user input.
package retention

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// aggregateTables lists the rollup tables the sweep prunes and how each stores its
// timestamp. traffic_usage is intentionally excluded — it has no time-based retention
// (cleared manually only).
var aggregateTables = []struct {
	name string
	col  string // time column
	unix bool   // true = unix seconds, false = SQLite datetime string
}{
	{"fleet_metrics", "bucket", true},
	{"fw_drop_samples", "ts", false},
	{"l7_block_samples", "ts", false},
	{"log_rollups", "bucket_hour", true},
}

// Sweep deletes rows older than `days` from every aggregate table. Best-effort per
// table (one failure doesn't stop the rest). days < 1 is a no-op so a misconfiguration
// can never wipe the tables.
func Sweep(db *sql.DB, days int) {
	if db == nil || days < 1 {
		return
	}
	for _, t := range aggregateTables {
		var err error
		if t.unix {
			cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
			// t.name/t.col are constants from aggregateTables — no injection surface.
			_, err = db.Exec(fmt.Sprintf("DELETE FROM %s WHERE %s < ?", t.name, t.col), cutoff)
		} else {
			_, err = db.Exec(fmt.Sprintf("DELETE FROM %s WHERE %s < datetime('now', ?)", t.name, t.col), fmt.Sprintf("-%d days", days))
		}
		if err != nil {
			log.Printf("retention: prune %s: %v", t.name, err)
		}
	}
}

// Start prunes once at boot then daily. days() is read each run, so a changed retention
// setting takes effect on the next sweep (and the settings save also triggers Sweep now).
func Start(ctx context.Context, db *sql.DB, days func() int) {
	Sweep(db, days())
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			Sweep(db, days())
		}
	}
}
