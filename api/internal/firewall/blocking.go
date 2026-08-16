package firewall

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/events"
	"api/internal/logs/sources"
	"api/internal/nftables"
)

// BlockNotifyFunc is called when an IP is blocked (for push notifications)
type BlockNotifyFunc func(ip, reason string)

var (
	blockNotifyCallback BlockNotifyFunc
	blockNotifyMu       sync.RWMutex
)

// SetBlockNotifyCallback sets the callback for block notifications
func SetBlockNotifyCallback(fn BlockNotifyFunc) {
	blockNotifyMu.Lock()
	defer blockNotifyMu.Unlock()
	blockNotifyCallback = fn
}

// blockIP blocks an IP address from a jail
func (s *Service) blockIP(ip, jailName, reason string, banTime int) {
	s.blockIPWithOptions(ip, jailName, reason, banTime, false, "jail:"+jailName)
}

// blockIPWithOptions blocks an IP with additional options
func (s *Service) blockIPWithOptions(ip, jailName, reason string, banTime int, isRange bool, source string) {
	// This panel is IPv4-only; the nftables blocked sets are ipv4_addr. An IPv6 value
	// here would be rejected by the kernel and break the atomic ruleset reload, so skip
	// it. External IPv6 is already dropped wholesale at the firewall, so nothing is lost.
	if !isIPv4Value(ip) {
		log.Printf("firewall: skipping auto-block of non-IPv4 address %q (jail: %s) — panel is IPv4-only", ip, jailName)
		return
	}

	// Self-protection on the automated path (the manual path has validateIPNotProtected):
	// never auto-ban the server's own IP or loopback — a spoofed/misparsed log line must not
	// lock the panel out of its own services.
	if (s.config.ServerIP != "" && ip == s.config.ServerIP) || strings.HasPrefix(ip, "127.") {
		log.Printf("firewall: refusing to auto-block protected IP %s (jail: %s)", ip, jailName)
		return
	}

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

		// Send push notification for block (async)
		go func() {
			blockNotifyMu.RLock()
			notifyFn := blockNotifyCallback
			blockNotifyMu.RUnlock()
			if notifyFn != nil {
				notifyFn(ip, jailName+": "+reason)
			}
		}()

		// Check for auto-escalation (only for individual IPs, not ranges)
		if entryType == nftables.EntryTypeIP {
			s.checkEscalation(ip, jailName, banTime)
			s.checkASNEscalation(ip, jailName, banTime)
		}
	}
}

// checkASNEscalation blocks the whole ASN when enough distinct IPs from it have
// been banned by this jail within the escalation window. Off unless the jail has
// escalate_asn set. Each banned IP's ASN is resolved on demand (bans are rare),
// which avoids adding an asn column to the large firewall_entries table.
func (s *Service) checkASNEscalation(ip, jailName string, banTime int) {
	if s.geo == nil {
		return
	}

	var escalateASN bool
	var threshold, window int
	err := s.db.QueryRow(`SELECT COALESCE(escalate_asn, 0), COALESCE(escalate_asn_threshold, 15), COALESCE(escalate_asn_window, 3600)
		FROM jails WHERE name = ?`, jailName).Scan(&escalateASN, &threshold, &window)
	if err != nil || !escalateASN {
		return
	}

	asn := s.geo.ASNForIP(ip)
	if asn == 0 {
		return // unknown owner — cannot escalate
	}

	// Count distinct IPs banned by this jail in the window that belong to this ASN.
	// Only currently-active bans count (enabled + unexpired) — a manually-unblocked or
	// expired entry is not evidence, and escalating a whole ASN (millions of IPs) on
	// stale bans would be an over-block. Matches the "currently banned" semantics used
	// by the jail count queries.
	rows, err := s.db.Query(`SELECT DISTINCT value FROM firewall_entries
		WHERE entry_type = 'ip' AND action = 'block' AND name = ?
		  AND enabled = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
		  AND created_at > datetime('now', '-' || ? || ' seconds')`, jailName, window)
	if err != nil {
		return
	}
	count := 0
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil && s.geo.ASNForIP(v) == asn {
			count++
		}
	}
	rows.Close()
	if count < threshold {
		return
	}

	// Already escalated? Skip so we don't re-cache + re-apply on every later ban.
	asnStr := strconv.FormatUint(uint64(asn), 10)
	var already int
	s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'asn' AND value = ? AND action = 'block' AND enabled = 1`, asnStr).Scan(&already)
	if already > 0 {
		return
	}

	// Size floor: never let auto-escalation block a huge provider (cloud/CDN). An attacker
	// rotating source IPs through such an ASN could otherwise force a massive collateral
	// block. Above the ceiling, skip auto-escalation — a large ASN can still be blocked
	// manually, deliberately.
	const maxAutoEscalateASNAddrs = 1 << 16 // a /16 worth; clouds are far larger
	if s.geo != nil {
		var addrs uint64
		for _, c := range s.geo.ASNRangesV4(asn) {
			if _, ipnet, err := net.ParseCIDR(c); err == nil {
				ones, bits := ipnet.Mask.Size()
				addrs += uint64(1) << uint(bits-ones)
			}
		}
		if addrs > maxAutoEscalateASNAddrs {
			log.Printf("firewall: skipping auto-escalation of AS%d — too large (%d addresses > %d ceiling); block it manually if intended", asn, addrs, maxAutoEscalateASNAddrs)
			return
		}
	}

	// Escalate: block the whole ASN.
	var expiresAt interface{}
	if banTime > 0 {
		expiresAt = time.Now().Add(time.Duration(banTime) * time.Second)
	}
	_, err = s.db.Exec(`INSERT INTO firewall_entries
		(entry_type, value, action, direction, protocol, source, reason, name, expires_at, enabled)
		VALUES ('asn', ?, 'block', 'inbound', 'both', 'escalated', ?, ?, ?, 1)
		ON CONFLICT(entry_type, value, protocol) DO NOTHING`,
		asnStr, fmt.Sprintf("Auto-escalated: %d IPs from AS%d banned", count, asn), jailName, expiresAt)
	if err != nil {
		log.Printf("Error inserting escalated ASN: %v", err)
		return
	}
	log.Printf("Auto-escalating: blocking AS%d (jail: %s, IPs: %d)", asn, jailName, count)

	// Expand + cache the provider's ranges so the next apply drops them.
	if n, err := s.geo.CacheASNZones(asn); err == nil {
		s.db.Exec("UPDATE firewall_entries SET hit_count = ? WHERE entry_type = 'asn' AND value = ?", n, asnStr)
	}
	events.Log("firewall", "asn_escalated", events.SeverityWarning,
		fmt.Sprintf("Escalated to AS%d — %d IPs from this provider banned by %s", asn, count, jailName))
	s.RequestApply()
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

	// Count distinct IPs from this subnet blocked within the escalation window. Only
	// currently-active bans count (enabled + unexpired) — matching checkASNEscalation, so a
	// manually-unblocked or expired ban isn't evidence for escalating to a whole /24.
	var count int
	err = s.db.QueryRow(`
		SELECT COUNT(DISTINCT value) FROM firewall_entries
		WHERE name = ?
		AND entry_type = 'ip'
		AND enabled = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
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
