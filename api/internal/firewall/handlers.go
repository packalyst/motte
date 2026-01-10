package firewall

import (
	"fmt"
	"log"
	"net/http"

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

	// Count blocked IPs/ranges
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type IN ('ip', 'range') AND action = 'block' AND enabled = 1
		AND (expires_at IS NULL OR expires_at > datetime('now'))`).Scan(&blockedCount)

	// Count allowed ports
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'port' AND action = 'allow' AND enabled = 1`).Scan(&portsCount)

	// Count blocked countries
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'country' AND enabled = 1`).Scan(&countryCount)

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
	if !router.DecodeJSONOrError(w, r, &s.config) {
		return
	}
	router.JSON(w, s.config)
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

	// Get DB counts - ports and countries
	var dbAllowedTCPPorts, dbAllowedUDPPorts, dbCountries int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'port' AND action = 'allow' AND enabled = 1
		AND protocol IN ('tcp', 'both')`).Scan(&dbAllowedTCPPorts)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'port' AND action = 'allow' AND enabled = 1
		AND protocol IN ('udp', 'both')`).Scan(&dbAllowedUDPPorts)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type = 'country' AND enabled = 1`).Scan(&dbCountries)

	// Get nftables set counts
	nftCounts := s.nft.GetFirewallSetCounts()

	// Compare counts to determine sync status
	inSync := nftStatus.InSync &&
		nftCounts["blocked_ips"] == dbBlockedIPsIn &&
		nftCounts["blocked_ranges"] == dbBlockedRangesIn &&
		nftCounts["blocked_ips_out"] == dbBlockedIPsOut &&
		nftCounts["blocked_ranges_out"] == dbBlockedRangesOut &&
		nftCounts["allowed_tcp_ports"] == dbAllowedTCPPorts &&
		nftCounts["allowed_udp_ports"] == dbAllowedUDPPorts

	router.JSON(w, map[string]interface{}{
		"inSync":           inSync,
		"applyPending":     nftStatus.ApplyPending,
		"lastApplyAt":      nftStatus.LastApplyAt,
		"lastApplyError":   nftStatus.LastApplyError,
		"tables":           nftStatus.Tables,
		"dbBlockedIPs":     dbBlockedIPsIn,
		"dbBlockedRanges":  dbBlockedRangesIn,
		"dbAllowedPorts":   dbAllowedTCPPorts + dbAllowedUDPPorts,
		"dbCountryRanges":  dbCountries,
		"nftBlockedIPs":    nftCounts["blocked_ips"],
		"nftBlockedRanges": nftCounts["blocked_ranges"],
		"nftAllowedPorts":  nftCounts["allowed_tcp_ports"] + nftCounts["allowed_udp_ports"],
	})
}

// Helper functions

// getDistinctValues returns distinct values from a column
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
