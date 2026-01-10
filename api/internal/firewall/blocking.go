package firewall

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"api/internal/logs/sources"
	"api/internal/nftables"
)

// blockIP blocks an IP address from a jail
func (s *Service) blockIP(ip, jailName, reason string, banTime int) {
	s.blockIPWithOptions(ip, jailName, reason, banTime, false, "jail:"+jailName)
}

// blockIPWithOptions blocks an IP with additional options
func (s *Service) blockIPWithOptions(ip, jailName, reason string, banTime int, isRange bool, source string) {
	var expiresAt interface{}
	if banTime > 0 {
		expiresAt = time.Now().Add(time.Duration(banTime) * time.Second)
	}

	entryType := nftables.EntryTypeIP
	if isRange || strings.Contains(ip, "/") {
		entryType = nftables.EntryTypeRange
	}

	// Use jailName as the "name" field for filtering
	_, err := s.db.Exec(`
		INSERT INTO firewall_entries (entry_type, value, action, direction, protocol, source, reason, name, expires_at, enabled, hit_count)
		VALUES (?, ?, 'block', 'inbound', 'both', ?, ?, ?, ?, 1, 1)
		ON CONFLICT(entry_type, value, protocol) DO UPDATE SET
			hit_count = hit_count + 1,
			created_at = CURRENT_TIMESTAMP,
			expires_at = excluded.expires_at,
			reason = excluded.reason
	`, entryType, ip, source, reason, jailName, expiresAt)

	if err == nil {
		log.Printf("Blocked IP %s (jail: %s, reason: %s, isRange: %v)", ip, jailName, reason, isRange)
		s.RequestApply()

		// Check for auto-escalation (only for individual IPs, not ranges)
		if entryType == nftables.EntryTypeIP {
			s.checkEscalation(ip, jailName, banTime)
		}
	}
}

// checkEscalation checks if we should escalate to blocking an entire /24 range
func (s *Service) checkEscalation(ip, jailName string, banTime int) {
	// Get jail's escalation settings
	var escalateEnabled bool
	var escalateThreshold, escalateWindow int
	err := s.db.QueryRow(`SELECT COALESCE(escalate_enabled, 0), COALESCE(escalate_threshold, 3), COALESCE(escalate_window, 3600)
		FROM jails WHERE name = ?`, jailName).Scan(&escalateEnabled, &escalateThreshold, &escalateWindow)
	if err != nil || !escalateEnabled {
		return
	}

	// Get the /24 subnet for this IP
	subnet := getSubnet24(ip)
	if subnet == "" {
		return
	}

	// Count distinct IPs from this subnet blocked within the escalation window
	var count int
	err = s.db.QueryRow(`
		SELECT COUNT(DISTINCT value) FROM firewall_entries
		WHERE name = ?
		AND entry_type = 'ip'
		AND value LIKE ?
		AND created_at > datetime('now', '-' || ? || ' seconds')
	`, jailName, strings.TrimSuffix(subnet, ".0/24")+".%", escalateWindow).Scan(&count)
	if err != nil {
		log.Printf("Error checking escalation: %v", err)
		return
	}

	log.Printf("Escalation check for %s: %d IPs from %s (threshold: %d)", jailName, count, subnet, escalateThreshold)

	if count >= escalateThreshold {
		// Block the entire /24 range
		log.Printf("Auto-escalating: blocking %s (jail: %s, IPs: %d)", subnet, jailName, count)

		var expiresAt interface{}
		if banTime > 0 {
			expiresAt = time.Now().Add(time.Duration(banTime) * time.Second)
		}

		// Insert the range block
		_, err := s.db.Exec(`
			INSERT INTO firewall_entries (entry_type, value, action, direction, protocol, source, reason, name, expires_at, enabled, hit_count)
			VALUES ('range', ?, 'block', 'inbound', 'both', 'escalated', ?, ?, ?, 1, ?)
			ON CONFLICT(entry_type, value, protocol) DO NOTHING
		`, subnet,
			fmt.Sprintf("Auto-escalated: %d IPs from this range blocked", count),
			jailName, expiresAt, count)

		if err != nil {
			log.Printf("Error inserting escalated range: %v", err)
			return
		}

		// Remove individual IPs that are now covered by the range
		result, err := s.db.Exec(`
			DELETE FROM firewall_entries
			WHERE name = ?
			AND entry_type = 'ip'
			AND value LIKE ?
		`, jailName, strings.TrimSuffix(subnet, ".0/24")+".%")
		if err == nil {
			if deleted, _ := result.RowsAffected(); deleted > 0 {
				log.Printf("Removed %d individual IPs now covered by range %s", deleted, subnet)
			}
		}

		s.RequestApply()
	}
}

// isIPBlocked checks if an IP is currently blocked (uses cache for performance)
func (s *Service) isIPBlocked(ip string) bool {
	s.refreshBlockCacheIfNeeded()

	s.blockCache.mu.RLock()
	defer s.blockCache.mu.RUnlock()

	// Check direct IP match
	if s.blockCache.blockedIPs[ip] {
		return true
	}

	// Check CIDR ranges
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, network := range s.blockCache.ranges {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// refreshBlockCacheIfNeeded refreshes the block cache if TTL has expired
func (s *Service) refreshBlockCacheIfNeeded() {
	s.blockCache.mu.RLock()
	needsRefresh := time.Since(s.blockCache.updatedAt) > s.blockCache.ttl
	s.blockCache.mu.RUnlock()

	if !needsRefresh {
		return
	}

	s.blockCache.mu.Lock()
	defer s.blockCache.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(s.blockCache.updatedAt) <= s.blockCache.ttl {
		return
	}

	// Load blocked IPs
	blockedIPs := make(map[string]bool)
	rows, err := s.db.Query(`
		SELECT value FROM firewall_entries
		WHERE entry_type = 'ip' AND enabled = 1
		AND (expires_at IS NULL OR expires_at > datetime('now'))
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ip string
			if rows.Scan(&ip) == nil {
				blockedIPs[ip] = true
			}
		}
	}

	// Load and parse CIDR ranges
	var ranges []*net.IPNet
	rows2, err := s.db.Query(`
		SELECT value FROM firewall_entries
		WHERE entry_type = 'range' AND enabled = 1
		AND (expires_at IS NULL OR expires_at > datetime('now'))
	`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var cidr string
			if rows2.Scan(&cidr) == nil {
				if _, network, err := net.ParseCIDR(cidr); err == nil {
					ranges = append(ranges, network)
				}
			}
		}
	}

	s.blockCache.blockedIPs = blockedIPs
	s.blockCache.ranges = ranges
	s.blockCache.updatedAt = time.Now()
}

// recordAttempt logs a connection attempt to unified logs
func (s *Service) recordAttempt(srcIP string, destPort int, protocol, jailName, action string) {
	sources.InsertFirewallLog(srcIP, destPort, protocol, jailName, action)
}
