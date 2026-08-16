package firewall

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"api/internal/helper"
	"api/internal/router"
)

// validSQLIdentifiers whitelists allowed table and column names for dynamic SQL
// This prevents SQL injection when interpolating identifiers
var validSQLIdentifiers = map[string]bool{
	// Tables
	"firewall_entries": true,
	"jails":            true,
	// Columns
	"jail_name":  true,
	"client_ip":  true,
	"entry_type": true,
	"source":     true,
	"protocol":   true,
	"value":      true,
}

// isValidSQLIdentifier checks if a table or column name is whitelisted
func isValidSQLIdentifier(name string) bool {
	if !validSQLIdentifiers[name] {
		log.Printf("Warning: invalid SQL identifier rejected: %s", name)
		return false
	}
	return true
}

// handleStatus returns firewall status summary
func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	var blockedCount, portsCount, countryCount, attemptsCount, jailsCount int

	// Count firewall entries in single query using conditional aggregation
	_ = s.db.QueryRow(`SELECT
		SUM(CASE WHEN entry_type IN ('ip', 'range') AND action = 'block' AND enabled = 1
		         AND (expires_at IS NULL OR expires_at > datetime('now')) THEN 1 ELSE 0 END),
		SUM(CASE WHEN entry_type = 'port' AND action = 'allow' AND enabled = 1 THEN 1 ELSE 0 END),
		SUM(CASE WHEN entry_type = 'country' AND enabled = 1 THEN 1 ELSE 0 END)
		FROM firewall_entries`).Scan(&blockedCount, &portsCount, &countryCount)

	// Count recent firewall log entries (last 24h)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM logs
		WHERE logs_type = 'fw' AND logs_timestamp > datetime('now', '-1 day')`).Scan(&attemptsCount)

	// Count active jails
	_ = s.db.QueryRow("SELECT COUNT(*) FROM jails WHERE enabled = 1").Scan(&jailsCount)

	// Get geo blocking status
	countryBlockingEnabled := false
	if s.geo != nil {
		countryBlockingEnabled = s.geo.IsBlockingEnabled()
	}

	router.JSON(w, map[string]interface{}{
		"blockedIPCount":         blockedCount,
		"allowedPorts":           portsCount,
		"blockedCountries":       countryCount,
		"recentAttempts":         attemptsCount,
		"activeJails":            jailsCount,
		"countryBlockingEnabled": countryBlockingEnabled,
		"sshPort":                helper.GetSSHPort(),
	})
}

// handleGetConfig returns current configuration
func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, s.config)
}

// handleUpdateConfig updates configuration
func (s *Service) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	// Decode into a COPY, never the live config: a bad request must not half-update it,
	// and the copy preserves the json:"-" internal fields (WgPort, ServerIP, …). Only
	// IgnoreNetworks and MaxAttempts are client-settable.
	s.configMu.RLock()
	updated := s.config
	s.configMu.RUnlock()

	if !router.DecodeJSONOrError(w, r, &updated) {
		return
	}

	// Validate the client-settable fields before they can affect the firewall/jails.
	for _, n := range updated.IgnoreNetworks {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(n))
		if err != nil {
			router.JSONError(w, "invalid ignore network "+n+": "+err.Error(), http.StatusBadRequest)
			return
		}
		// Reject 0.0.0.0/0 (and ::/0): an all-addresses ignore net makes isIgnoredNetwork
		// match every IP, silently disabling all blocking/auto-ban.
		if ones, _ := ipnet.Mask.Size(); ones == 0 {
			router.JSONError(w, "ignore network "+n+" is too broad — /0 would make the firewall ignore all traffic", http.StatusBadRequest)
			return
		}
	}
	if updated.MaxAttempts < 0 {
		router.JSONError(w, "maxAttempts cannot be negative", http.StatusBadRequest)
		return
	}

	// NOTE: the write is guarded; fully race-clean config reads (jail/traffic/utils) are a
	// deferred follow-up — see the config-race notes. Config changes are rare admin actions.
	s.configMu.Lock()
	s.config = updated
	s.configMu.Unlock()
	router.JSON(w, updated)
}

// handleApplyRules manually applies firewall rules
func (s *Service) handleApplyRules(w http.ResponseWriter, r *http.Request) {
	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "applied"})
}

// handleSyncStatus returns the sync status between DB and nftables
func (s *Service) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	nftStatus := s.GetSyncStatus()

	// Get DB counts - inbound (includes 'both')
	var dbBlockedIPsIn, dbBlockedRangesIn int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'ip' AND action = 'block' AND enabled = 1
		AND direction IN ('inbound', 'both')
		AND (expires_at IS NULL OR expires_at > datetime('now'))`).Scan(&dbBlockedIPsIn)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'range' AND action = 'block' AND enabled = 1
		AND direction IN ('inbound', 'both')
		AND (expires_at IS NULL OR expires_at > datetime('now'))`).Scan(&dbBlockedRangesIn)

	// Get DB counts - outbound (includes 'both')
	var dbBlockedIPsOut, dbBlockedRangesOut int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'ip' AND action = 'block' AND enabled = 1
		AND direction IN ('outbound', 'both')
		AND (expires_at IS NULL OR expires_at > datetime('now'))`).Scan(&dbBlockedIPsOut)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'range' AND action = 'block' AND enabled = 1
		AND direction IN ('outbound', 'both')
		AND (expires_at IS NULL OR expires_at > datetime('now'))`).Scan(&dbBlockedRangesOut)

	// Get DB counts - ports
	var dbAllowedTCPPorts, dbAllowedUDPPorts int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'port' AND action = 'allow' AND enabled = 1
		AND protocol IN ('tcp', 'both')`).Scan(&dbAllowedTCPPorts)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'port' AND action = 'allow' AND enabled = 1
		AND protocol IN ('udp', 'both')`).Scan(&dbAllowedUDPPorts)

	// Allow source-list: exact for 1:1 sets (ip/range).
	var dbAllowedIPs, dbAllowedRanges int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'ip' AND action = 'allow' AND enabled = 1
		AND (expires_at IS NULL OR expires_at > datetime('now'))`).Scan(&dbAllowedIPs)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'range' AND action = 'allow' AND enabled = 1
		AND (expires_at IS NULL OR expires_at > datetime('now'))`).Scan(&dbAllowedRanges)

	// Expanded interval sets (country/asn, block+allow) hold thousands of CIDRs
	// that nftables may merge, so exact counts aren't reliable. Presence check:
	// the set must be non-empty exactly when the DB has such rules.
	countEntries := func(entryType, action string) int {
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
			WHERE entry_type = ? AND action = ? AND enabled = 1`, entryType, action).Scan(&n)
		return n
	}
	dbBlockedCountries := countEntries("country", "block")
	dbBlockedASN := countEntries("asn", "block")
	dbAllowedCountries := countEntries("country", "allow")
	dbAllowedASN := countEntries("asn", "allow")

	// Get nftables set counts
	nftCounts := s.nft.GetFirewallSetCounts()

	present := func(dbCount, nftCount int) bool { return (dbCount > 0) == (nftCount > 0) }

	// Compare to determine sync status: exact for 1:1 sets, presence for expanded.
	inSync := nftStatus.InSync &&
		nftCounts["blocked_ips"] == dbBlockedIPsIn &&
		nftCounts["blocked_ranges"] == dbBlockedRangesIn &&
		nftCounts["blocked_ips_out"] == dbBlockedIPsOut &&
		nftCounts["blocked_ranges_out"] == dbBlockedRangesOut &&
		nftCounts["allowed_tcp_ports"] == dbAllowedTCPPorts &&
		nftCounts["allowed_udp_ports"] == dbAllowedUDPPorts &&
		nftCounts["allowed_ips"] == dbAllowedIPs &&
		present(dbAllowedRanges, nftCounts["allowed_ranges"]) &&
		present(dbBlockedCountries, nftCounts["blocked_countries"]) &&
		present(dbBlockedASN, nftCounts["blocked_asn"]) &&
		present(dbAllowedCountries, nftCounts["allowed_countries"]) &&
		present(dbAllowedASN, nftCounts["allowed_asn"])

	router.JSON(w, map[string]interface{}{
		"inSync":           inSync,
		"applyPending":     nftStatus.ApplyPending,
		"lastApplyAt":      nftStatus.LastApplyAt,
		"lastApplyError":   nftStatus.LastApplyError,
		"tables":           nftStatus.Tables,
		"dbBlockedIPs":     dbBlockedIPsIn,
		"dbBlockedRanges":  dbBlockedRangesIn,
		"dbAllowedPorts":   dbAllowedTCPPorts + dbAllowedUDPPorts,
		"dbCountryRanges":  dbBlockedCountries,
		"dbBlockedASN":     dbBlockedASN,
		"dbAllowedSources": dbAllowedIPs + dbAllowedRanges + dbAllowedCountries + dbAllowedASN,
		"nftBlockedIPs":    nftCounts["blocked_ips"],
		"nftBlockedRanges": nftCounts["blocked_ranges"],
		"nftBlockedASN":    nftCounts["blocked_asn"],
		"nftAllowedPorts":  nftCounts["allowed_tcp_ports"] + nftCounts["allowed_udp_ports"],
	})
}

// Helper functions

// getDistinctValues returns distinct values from a column
// getDistinctEntrySources returns the distinct `source` values among firewall
// entries, optionally restricted to a single action ("block"/"allow"). The
// blocked-entries filter passes action="block" so it only offers sources that
// actually appear on blocked rows — never allow-only sources like 'system'/
// 'docker', which would otherwise be dead options returning an empty list.
func (s *Service) getDistinctEntrySources(action string) []string {
	query := "SELECT DISTINCT source FROM firewall_entries"
	args := []interface{}{}
	if action == "block" || action == "allow" {
		query += " WHERE action = ?"
		args = append(args, action)
	}
	query += " ORDER BY source"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	values := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err == nil && v != "" {
			values = append(values, v)
		}
	}
	return values
}

func (s *Service) getDistinctValues(table, column string) []string {
	if !isValidSQLIdentifier(table) || !isValidSQLIdentifier(column) {
		return []string{}
	}

	query := fmt.Sprintf("SELECT DISTINCT %s FROM %s ORDER BY %s", column, table, column)

	rows, err := s.db.Query(query)
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	values := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			continue
		}
		values = append(values, v)
	}
	return values
}
