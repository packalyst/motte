package logs

import "log"

// rollupBackfillMarker records that the one-time logs→log_rollups backfill has run, so a
// later boot never re-scans the whole logs table.
const rollupBackfillMarker = "log_rollups_backfilled"

// backfillRollups seeds log_rollups from the rows already in `logs`, ONCE. The rollup
// trigger (see database.go) only accumulates rows inserted AFTER it was created, so on an
// existing DB the longer analytics periods would read an empty rollup until enough new
// logs pile up. This backfill compresses the history that's already on disk.
//
// Two guards keep it safe and cheap:
//   - a settings marker, so it runs a single time and never re-scans logs afterward;
//   - ON CONFLICT DO NOTHING, so any hour the trigger already recorded since deploy is
//     left untouched — the backfill only fills the older hours the trigger never saw, so
//     nothing is ever double-counted.
//
// The aggregate expressions MUST match the trigger in database.go (blocked/cached/ok), or
// backfilled buckets would disagree with trigger-filled ones.
func (s *Service) backfillRollups() {
	var done string
	s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, rollupBackfillMarker).Scan(&done)
	if done == "1" {
		return
	}
	res, err := s.db.Exec(`
		INSERT INTO log_rollups (bucket_hour, logs_type, cnt, bytes, blocked, cached, ok)
		SELECT (CAST(strftime('%s', logs_timestamp) AS INTEGER) / 3600) * 3600 AS bh,
		       logs_type,
		       COUNT(*),
		       COALESCE(SUM(logs_bytes), 0),
		       SUM(CASE WHEN logs_status LIKE '%BLOCK%' OR logs_status LIKE '%FILTER%' THEN 1 ELSE 0 END),
		       COALESCE(SUM(logs_cached), 0),
		       SUM(CASE WHEN CAST(logs_status AS INTEGER) BETWEEN 200 AND 299 THEN 1 ELSE 0 END)
		FROM logs
		WHERE logs_timestamp IS NOT NULL AND logs_timestamp != ''
		GROUP BY bh, logs_type
		ON CONFLICT(bucket_hour, logs_type) DO NOTHING`)
	if err != nil {
		// Leave the marker unset so it retries next boot rather than silently skipping.
		log.Printf("logs: rollup backfill failed: %v", err)
		return
	}
	n, _ := res.RowsAffected()
	if _, err := s.db.Exec(`
		INSERT INTO settings (key, value, encrypted, updated_at)
		VALUES (?, '1', 0, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = '1', updated_at = CURRENT_TIMESTAMP`,
		rollupBackfillMarker); err != nil {
		log.Printf("logs: rollup backfill marker save failed: %v", err)
		return
	}
	log.Printf("logs: rollup backfill seeded %d hourly buckets from existing logs", n)
}
