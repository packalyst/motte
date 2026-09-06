package logs

import (
	"log"
)

// cleanup enforces max entries per type. Registered as the "logs-cleanup" routine.
func (s *Service) cleanup() {
	maxPerType := s.config.MaxEntries / len(AllLogTypes)
	if maxPerType < 1 {
		maxPerType = 1 // never let a misconfig delete every row
	}

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
