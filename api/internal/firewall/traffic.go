package firewall

import (
	"log"
	"time"
)

// runExpirationCleanup periodically cleans up expired bans and old data
func (s *Service) runExpirationCleanup() {
	ticker := time.NewTicker(time.Duration(s.config.CleanupInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Expiration cleanup stopping (context cancelled)")
			return
		case <-ticker.C:
			s.cleanupExpiredData()
		}
	}
}

// cleanupExpiredData removes expired bans
func (s *Service) cleanupExpiredData() {
	// Remove expired entries from firewall_entries
	result, err := s.db.Exec("DELETE FROM firewall_entries WHERE expires_at IS NOT NULL AND expires_at < datetime('now')")
	if err == nil {
		if count, _ := result.RowsAffected(); count > 0 {
			log.Printf("Cleaned up %d expired firewall entries", count)
			s.RequestApply()
		}
	}
}
