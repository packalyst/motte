package logs

import (
	"log"
	"time"
)

// runCleanup periodically enforces max entries limit
func (s *Service) runCleanup() {
	ticker := time.NewTicker(time.Duration(s.config.CleanupInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Cleanup job stopping")
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

// cleanup enforces max entries per type
func (s *Service) cleanup() {
	maxPerType := s.config.MaxEntries / len(AllLogTypes)

	for _, logTypeInfo := range AllLogTypes {
		logType := logTypeInfo.Value
		result, err := s.db.Exec(`
			DELETE FROM logs
			WHERE logs_type = ?
			  AND logs_id NOT IN (
				SELECT logs_id FROM logs
				WHERE logs_type = ?
				ORDER BY logs_timestamp DESC
				LIMIT ?
			  )
		`, logType, logType, maxPerType)

		if err == nil {
			if count, _ := result.RowsAffected(); count > 0 {
				log.Printf("Cleaned up %d old %s logs", count, logType)
			}
		}
	}
}
