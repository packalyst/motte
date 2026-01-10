package auth

import (
	"log"
	"time"
)

const sessionCleanupInterval = 1 * time.Hour

// Start begins background tasks like session cleanup
func (s *Service) Start() {
	go s.runSessionCleanup()
}

// runSessionCleanup periodically removes expired sessions
func (s *Service) runSessionCleanup() {
	ticker := time.NewTicker(sessionCleanupInterval)
	defer ticker.Stop()

	// Run once at startup
	s.cleanupExpiredSessions()

	for range ticker.C {
		s.cleanupExpiredSessions()
	}
}

// cleanupExpiredSessions removes sessions past their expiry time
func (s *Service) cleanupExpiredSessions() {
	result, err := s.db.Exec("DELETE FROM sessions WHERE expires_at < datetime('now')")
	if err != nil {
		log.Printf("Session cleanup error: %v", err)
		return
	}

	if count, _ := result.RowsAffected(); count > 0 {
		log.Printf("Cleaned up %d expired sessions", count)
	}
}
