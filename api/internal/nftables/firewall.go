package nftables

import (
	"database/sql"
	"log"
	"net"
	"sort"
	"strings"

	"api/internal/database"
)

// FirewallTable builds the inet firewall table
type FirewallTable struct {
	db              *database.DB
	countryProvider CountryZonesProvider
}

// NewFirewallTable creates a new firewall table builder
func NewFirewallTable(db *database.DB, countryProvider CountryZonesProvider) *FirewallTable {
	return &FirewallTable{db: db, countryProvider: countryProvider}
}

func (t *FirewallTable) Name() string     { return "wgadmin_firewall" }
func (t *FirewallTable) Family() string   { return "inet" }
func (t *FirewallTable) Priority() int    { return 10 }

// Build generates the nftables script
func (t *FirewallTable) Build() (string, error) {
	// Clean overlapping ranges first
	if removed := t.cleanOverlappingRanges(); removed > 0 {
		log.Printf("nftables/firewall: cleaned %d overlapping ranges", removed)
	}

	// Load entries
	entries, err := t.loadEntries()
	if err != nil {
		return "", err
	}

	// Categorize entries by direction
	var blockedIPsIn, blockedIPsOut []string
	var blockedRangesIn, blockedRangesOut []string
	var allowedTCPPorts, allowedUDPPorts []string

	for _, e := range entries {
		if !e.Enabled {
			continue
		}

		switch e.EntryType {
		case EntryTypeIP:
			if e.Action == ActionBlock {
				if e.Direction == DirectionInbound || e.Direction == DirectionBoth {
					blockedIPsIn = append(blockedIPsIn, e.Value)
				}
				if e.Direction == DirectionOutbound || e.Direction == DirectionBoth {
					blockedIPsOut = append(blockedIPsOut, e.Value)
				}
			}
		case EntryTypeRange:
			if e.Action == ActionBlock {
				if e.Direction == DirectionInbound || e.Direction == DirectionBoth {
					blockedRangesIn = append(blockedRangesIn, e.Value)
				}
				if e.Direction == DirectionOutbound || e.Direction == DirectionBoth {
					blockedRangesOut = append(blockedRangesOut, e.Value)
				}
			}
		case EntryTypePort:
			if e.Action == ActionAllow {
				switch e.Protocol {
				case ProtocolTCP:
					allowedTCPPorts = append(allowedTCPPorts, e.Value)
				case ProtocolUDP:
					allowedUDPPorts = append(allowedUDPPorts, e.Value)
				case ProtocolBoth:
					allowedTCPPorts = append(allowedTCPPorts, e.Value)
					allowedUDPPorts = append(allowedUDPPorts, e.Value)
				}
			}
		case EntryTypeCountry:
			// Countries handled separately via countryProvider
		}
	}

	// Get country ranges from geolocation provider
	var countryRangesIn, countryRangesOut []string
	if t.countryProvider != nil {
		if cidrs, err := t.countryProvider.GetAllBlockedCIDRs(false); err == nil {
			countryRangesIn = cidrs
		}
		if cidrs, err := t.countryProvider.GetAllBlockedCIDRs(true); err == nil {
			countryRangesOut = cidrs
		}
	}

	return t.buildScript(
		blockedIPsIn, blockedIPsOut,
		blockedRangesIn, blockedRangesOut,
		allowedTCPPorts, allowedUDPPorts,
		countryRangesIn, countryRangesOut,
	), nil
}

func (t *FirewallTable) loadEntries() ([]FirewallEntry, error) {
	rows, err := t.db.Query(`
		SELECT id, entry_type, value, action, direction, protocol, source,
		       COALESCE(reason, ''), COALESCE(name, ''), essential,
		       expires_at, enabled, hit_count, created_at
		FROM firewall_entries
		WHERE enabled = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
		ORDER BY entry_type, created_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []FirewallEntry
	for rows.Next() {
		var e FirewallEntry
		var expiresAt sql.NullTime
		err := rows.Scan(
			&e.ID, &e.EntryType, &e.Value, &e.Action, &e.Direction, &e.Protocol,
			&e.Source, &e.Reason, &e.Name, &e.Essential, &expiresAt, &e.Enabled,
			&e.HitCount, &e.CreatedAt,
		)
		if err != nil {
			log.Printf("nftables/firewall: scan error: %v", err)
			continue
		}
		e.ExpiresAt = database.TimePointerFromNull(expiresAt)
		entries = append(entries, e)
	}

	return entries, nil
}

// cleanOverlappingRanges removes CIDR ranges fully contained in larger ranges
func (t *FirewallTable) cleanOverlappingRanges() int {
	rows, err := t.db.Query(`
		SELECT id, value FROM firewall_entries
		WHERE entry_type = 'range' AND enabled = 1
		AND (expires_at IS NULL OR expires_at > datetime('now'))
	`)
	if err != nil {
		return 0
	}
	defer rows.Close()

	type rangeInfo struct {
		id    int64
		cidr  string
		start uint32
		end   uint32
	}

	var ranges []rangeInfo
	for rows.Next() {
		var id int64
		var cidr string
		if err := rows.Scan(&id, &cidr); err != nil {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ip4 := network.IP.To4()
		if ip4 == nil {
			continue
		}
		start := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		ones, _ := network.Mask.Size()
		size := uint32(1) << (32 - ones)
		ranges = append(ranges, rangeInfo{id: id, cidr: cidr, start: start, end: start + size - 1})
	}

	if len(ranges) < 2 {
		return 0
	}

	// Sort by start, then by size (larger first)
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end > ranges[j].end
		}
		return ranges[i].start < ranges[j].start
	})

	// Find fully contained ranges
	var toDelete []int64
	var currentEnd uint32

	for _, r := range ranges {
		if currentEnd > 0 && r.start <= currentEnd && r.end <= currentEnd {
			toDelete = append(toDelete, r.id)
		} else if r.end > currentEnd {
			currentEnd = r.end
		}
	}

	// Batch delete
	if len(toDelete) == 0 {
		return 0
	}

	placeholders := make([]string, len(toDelete))
	args := make([]interface{}, len(toDelete))
	for i, id := range toDelete {
		placeholders[i] = "?"
		args[i] = id
	}

	query := "DELETE FROM firewall_entries WHERE id IN (" + strings.Join(placeholders, ",") + ")"
	result, err := t.db.Exec(query, args...)
	if err != nil {
		return 0
	}

	deleted, _ := result.RowsAffected()
	return int(deleted)
}

func (t *FirewallTable) buildScript(blockedIPsIn, blockedIPsOut, blockedRangesIn, blockedRangesOut, tcpPorts, udpPorts, countryIn, countryOut []string) string {
	var sb strings.Builder

	sb.WriteString(TableHeader("inet", "wgadmin_firewall"))

	// Sets - inbound
	sb.WriteString(BuildSet("blocked_ips", "ipv4_addr", nil, blockedIPsIn))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_ranges", "ipv4_addr", []string{"interval"}, blockedRangesIn))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_countries", "ipv4_addr", []string{"interval"}, countryIn))
	sb.WriteString("\n")
	// Sets - outbound
	sb.WriteString(BuildSet("blocked_ips_out", "ipv4_addr", nil, blockedIPsOut))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_ranges_out", "ipv4_addr", []string{"interval"}, blockedRangesOut))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_countries_out", "ipv4_addr", []string{"interval"}, countryOut))
	sb.WriteString("\n")
	// Sets - ports
	sb.WriteString(BuildSet("allowed_tcp_ports", "inet_service", nil, tcpPorts))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("allowed_udp_ports", "inet_service", nil, udpPorts))
	sb.WriteString("\n")

	// Input chain - traffic destined TO the server (check source address)
	sb.WriteString(BuildChain("input", "filter", "input", 0, "drop", []string{
		"# Allow established connections",
		"ct state established,related accept",
		"",
		"# Allow loopback interface",
		"iif lo accept",
		"",
		"# Allow ICMP/ping",
		"ip protocol icmp accept",
		"ip6 nexthdr icmpv6 accept",
		"",
		"# Drop traffic FROM blocked sources (saddr)",
		"ip saddr @blocked_ips drop",
		"ip saddr @blocked_ranges drop",
		"ip saddr @blocked_countries drop",
		"",
		"# Allow specific ports",
		"tcp dport @allowed_tcp_ports accept",
		"udp dport @allowed_udp_ports accept",
		"",
		"# Log and drop everything else",
		`limit rate 5/minute log prefix "FIREWALL_DROP: " drop`,
	}))
	sb.WriteString("\n")

	// Forward chain - traffic routed THROUGH the server (VPN clients)
	// Needs both saddr (block bad sources) and daddr (block bad destinations)
	sb.WriteString(BuildChain("forward", "filter", "forward", -1, "accept", []string{
		"# Allow established connections",
		"ct state established,related accept",
		"",
		"# Drop traffic FROM blocked sources (saddr)",
		"ip saddr @blocked_ips drop",
		"ip saddr @blocked_ranges drop",
		"ip saddr @blocked_countries drop",
		"",
		"# Drop traffic TO blocked destinations (daddr)",
		"ip daddr @blocked_ips_out drop",
		"ip daddr @blocked_ranges_out drop",
		"ip daddr @blocked_countries_out drop",
		"",
		"# Log and allow VPN traffic",
		`iifname "wg0" ct state new log prefix "VPN_TRAFFIC: " accept`,
		`oifname "wg0" accept`,
		`iifname "tailscale0" ct state new log prefix "VPN_TRAFFIC: " accept`,
		`oifname "tailscale0" accept`,
	}))
	sb.WriteString("\n")

	// Output chain - traffic originating FROM the server (check destination address)
	sb.WriteString(BuildChain("output", "filter", "output", 0, "accept", []string{
		"# Allow established connections",
		"ct state established,related accept",
		"",
		"# Drop traffic TO blocked destinations (daddr)",
		"ip daddr @blocked_ips_out drop",
		"ip daddr @blocked_ranges_out drop",
		"ip daddr @blocked_countries_out drop",
	}))

	sb.WriteString(TableFooter())

	return sb.String()
}
