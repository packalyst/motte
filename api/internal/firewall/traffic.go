package firewall

import (
	"log"
)

// cleanupExpiredData removes expired bans. Registered as the "firewall-cleanup"
// routine (see service.go).
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
