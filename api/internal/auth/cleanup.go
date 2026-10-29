package auth

import (
	"context"
	"fmt"
	"log"
	"time"

	"api/internal/routines"
)

const sessionCleanupInterval = 1 * time.Hour

// Start registers this service's background routines with the supervisor so they
// are visible/controllable on the Routines page.
func (s *Service) Start() {
	routines.Register(routines.Spec{
		Name:        "session-cleanup",
		Description: "Delete expired user sessions",
		Interval:    sessionCleanupInterval,
		RunAtStart:  true,
		Run:         func(context.Context) error { return s.cleanupExpiredSessions() },
	})
}

// cleanupExpiredSessions removes sessions past their expiry time.
func (s *Service) cleanupExpiredSessions() error {
	result, err := s.db.Exec("DELETE FROM sessions WHERE expires_at < datetime('now')")
	if err != nil {
		return fmt.Errorf("session cleanup: %w", err)
	}
	if count, _ := result.RowsAffected(); count > 0 {
		log.Printf("Cleaned up %d expired sessions", count)
	}
	return nil
}
