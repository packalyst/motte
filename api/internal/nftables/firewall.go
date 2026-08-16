package nftables

import (
	"database/sql"
	"log"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"api/internal/database"
)

// isValidPortElement guards the inet_service set boundary: a numeric port 1-65535 or a
// strict N-M range. Mirrors the ValidateIPv4OrCIDR boundary for address sets, so a bad
// value can't reach the set and break the atomic reload.
func isValidPortElement(s string) bool {
	s = strings.TrimSpace(s)
	if a, b, ok := strings.Cut(s, "-"); ok {
		return validPortNum(a) && validPortNum(b)
	}
	return validPortNum(s)
}

func validPortNum(s string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return err == nil && n >= 1 && n <= 65535
}

// keepIPv4CIDRs drops any element that isn't a valid IPv4 address/CIDR — a boundary guard
// for provider-sourced (country/ASN) ranges before they enter ipv4_addr sets, so a corrupt
// cache row can't wedge the atomic reload. Mirrors the per-entry filter in Build.
func keepIPv4CIDRs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		if ValidateIPv4OrCIDR(c) {
			out = append(out, c)
		}
	}
	return out
}

// detectWANInterface returns the interface name of the default IPv4 route.
// Re-detected on every script render so cable swaps / wifi changes self-heal.
// Returns "" if detection fails (e.g. no default route) — caller must skip the rule.
func detectWANInterface() string {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	// Output shape: "default via 192.168.1.1 dev eth0 proto dhcp ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// loadNoInternetPeerIPs returns IPs of all VPN peers that have block_internet = 1.
func loadNoInternetPeerIPs(db *database.DB) []string {
	rows, err := db.Query(`SELECT ip FROM vpn_clients WHERE block_internet = 1`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil && ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

// FirewallTable builds the inet firewall table
type FirewallTable struct {
	db              *database.DB
	countryProvider CountryZonesProvider
	asnProvider     ASNZonesProvider
}

// NewFirewallTable creates a new firewall table builder
func NewFirewallTable(db *database.DB, countryProvider CountryZonesProvider, asnProvider ASNZonesProvider) *FirewallTable {
	return &FirewallTable{db: db, countryProvider: countryProvider, asnProvider: asnProvider}
}

func (t *FirewallTable) Name() string   { return "wgadmin_firewall" }
func (t *FirewallTable) Family() string { return "inet" }
func (t *FirewallTable) Priority() int  { return 10 }

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
	var allowedIPs, allowedRanges []string // source allow-list (saddr accept)
	var allowedTCPPorts, allowedUDPPorts []string

	for _, e := range entries {
		if !e.Enabled {
			continue
		}

		switch e.EntryType {
		case EntryTypeIP:
			// The firewall sets are ipv4_addr; an IPv6 value would produce an invalid
			// element and wedge the whole atomic table. Skip it — external IPv6 is
			// already dropped wholesale on the WAN, so an IPv6 block entry is a no-op anyway.
			if !ValidateIPv4OrCIDR(e.Value) {
				continue
			}
			if e.Action == ActionBlock {
				if e.Direction == DirectionInbound || e.Direction == DirectionBoth {
					blockedIPsIn = append(blockedIPsIn, e.Value)
				}
				if e.Direction == DirectionOutbound || e.Direction == DirectionBoth {
					blockedIPsOut = append(blockedIPsOut, e.Value)
				}
			} else if e.Action == ActionAllow {
				allowedIPs = append(allowedIPs, e.Value)
			}
		case EntryTypeRange:
			if !ValidateIPv4OrCIDR(e.Value) {
				continue
			}
			if e.Action == ActionBlock {
				if e.Direction == DirectionInbound || e.Direction == DirectionBoth {
					blockedRangesIn = append(blockedRangesIn, e.Value)
				}
				if e.Direction == DirectionOutbound || e.Direction == DirectionBoth {
					blockedRangesOut = append(blockedRangesOut, e.Value)
				}
			} else if e.Action == ActionAllow {
				allowedRanges = append(allowedRanges, e.Value)
			}
		case EntryTypePort:
			if !isValidPortElement(e.Value) {
				continue
			}
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

	// Get country ranges from geolocation provider (blocked + allowed)
	var countryRangesIn, countryRangesOut, allowedCountries []string
	if t.countryProvider != nil {
		if cidrs, err := t.countryProvider.GetAllBlockedCIDRs(false); err == nil {
			countryRangesIn = cidrs
		}
		if cidrs, err := t.countryProvider.GetAllBlockedCIDRs(true); err == nil {
			countryRangesOut = cidrs
		}
		if cidrs, err := t.countryProvider.GetAllowedCountryCIDRs(); err == nil {
			allowedCountries = cidrs
		}
	}

	// Get ASN ranges from geolocation provider (blocked + allowed)
	var asnRangesIn, asnRangesOut, allowedASN []string
	if t.asnProvider != nil {
		if cidrs, err := t.asnProvider.GetBlockedASNCIDRs(false); err == nil {
			asnRangesIn = cidrs
		}
		if cidrs, err := t.asnProvider.GetBlockedASNCIDRs(true); err == nil {
			asnRangesOut = cidrs
		}
		if cidrs, err := t.asnProvider.GetAllowedASNCIDRs(); err == nil {
			allowedASN = cidrs
		}
	}

	// Boundary guard: drop any non-IPv4 element from provider-sourced ranges before they
	// enter the ipv4_addr sets, so a corrupt cache row can't wedge the atomic reload.
	countryRangesIn, countryRangesOut = keepIPv4CIDRs(countryRangesIn), keepIPv4CIDRs(countryRangesOut)
	allowedCountries = keepIPv4CIDRs(allowedCountries)
	asnRangesIn, asnRangesOut = keepIPv4CIDRs(asnRangesIn), keepIPv4CIDRs(asnRangesOut)
	allowedASN = keepIPv4CIDRs(allowedASN)

	// Per-peer WAN block: list of VPN peer IPs whose internet egress should be dropped.
	// WAN interface (default-route NIC) is detected dynamically and reused for both the
	// external-IPv6 drop and the per-peer WAN egress block. "" if detection fails.
	noInternetPeers := loadNoInternetPeerIPs(t.db)
	wanIface := detectWANInterface()
	if wanIface == "" && len(noInternetPeers) > 0 {
		log.Printf("nftables/firewall: %d peers flagged block_internet but WAN interface could not be detected; rule skipped", len(noInternetPeers))
	}

	return t.buildScript(scriptParams{
		blockedIPsIn: blockedIPsIn, blockedIPsOut: blockedIPsOut,
		blockedRangesIn: blockedRangesIn, blockedRangesOut: blockedRangesOut,
		tcpPorts: allowedTCPPorts, udpPorts: allowedUDPPorts,
		countryIn: countryRangesIn, countryOut: countryRangesOut,
		asnIn: asnRangesIn, asnOut: asnRangesOut,
		allowedIPs: allowedIPs, allowedRanges: allowedRanges,
		allowedCountries: allowedCountries, allowedASN: allowedASN,
		noInternetPeers: noInternetPeers, wanIface: wanIface,
	}), nil
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

// cleanOverlappingRanges removes blocked CIDR ranges fully contained in a larger
// blocked range (redundant in the drop set). Scoped to action='block': an allow
// range is an intentional exception that may deliberately sit inside a broader
// block, so it must never be merged/deleted.
func (t *FirewallTable) cleanOverlappingRanges() int {
	rows, err := t.db.Query(`
		SELECT id, value FROM firewall_entries
		WHERE entry_type = 'range' AND action = 'block' AND enabled = 1
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

// scriptParams groups the many element slices for buildScript. Named fields
// (rather than a long positional list) make argument-order mistakes impossible
// in this security-critical builder.
type scriptParams struct {
	blockedIPsIn, blockedIPsOut       []string
	blockedRangesIn, blockedRangesOut []string
	tcpPorts, udpPorts                []string
	countryIn, countryOut             []string
	asnIn, asnOut                     []string
	allowedIPs, allowedRanges         []string // source allow-list (saddr accept)
	allowedCountries, allowedASN      []string
	noInternetPeers                   []string
	wanIface                          string
}

// allowAndSaddrDropRules emits the shared "trusted-source allow + blocked-source drop"
// block used by BOTH the input and forward chains, so the two can never drift apart.
//
// Precedence and, crucially, SCOPE differ by allow type:
//   - @allowed_ips / @allowed_ranges are explicit single hosts/ranges an admin chose to
//     trust — a full accept (all ports) is the intent.
//   - A country/ASN *allow* entry may span millions of IPs, so it must NEVER become an
//     all-port accept in a default-drop chain (that would expose SSH/admin to a whole
//     country). Instead it only EXEMPTS its sources from the geo/ASN drops — the traffic
//     then falls through to the port allow-list. Specific IP/range blocks still win over
//     a broad country/ASN allow.
func allowAndSaddrDropRules() []string {
	return []string{
		"# Always-allow explicit trusted hosts/ranges (VIP list) — full accept, before drops",
		"ip saddr @allowed_ips accept",
		"ip saddr @allowed_ranges accept",
		"",
		"# Drop blocked sources (saddr). A country/ASN allow exempts its IPs from the geo/ASN",
		"# drops ONLY (still port-gated) — it is deliberately not an all-port accept.",
		"ip saddr @blocked_ips drop",
		"ip saddr @blocked_ranges drop",
		"ip saddr @blocked_countries ip saddr != @allowed_countries ip saddr != @allowed_asn drop",
		"ip saddr @blocked_asn ip saddr != @allowed_countries ip saddr != @allowed_asn drop",
	}
}

func (t *FirewallTable) buildScript(p scriptParams) string {
	blockedIPsIn, blockedIPsOut := p.blockedIPsIn, p.blockedIPsOut
	blockedRangesIn, blockedRangesOut := p.blockedRangesIn, p.blockedRangesOut
	tcpPorts, udpPorts := p.tcpPorts, p.udpPorts
	countryIn, countryOut := p.countryIn, p.countryOut
	asnIn, asnOut := p.asnIn, p.asnOut
	noInternetPeers, wanIface := p.noInternetPeers, p.wanIface

	var sb strings.Builder

	sb.WriteString(TableHeader("inet", "wgadmin_firewall"))

	// Sets - inbound
	sb.WriteString(BuildSet("blocked_ips", "ipv4_addr", nil, blockedIPsIn))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_ranges", "ipv4_addr", []string{"interval", "auto-merge"}, blockedRangesIn))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_countries", "ipv4_addr", []string{"interval", "auto-merge"}, countryIn))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_asn", "ipv4_addr", []string{"interval", "auto-merge"}, asnIn))
	sb.WriteString("\n")
	// Sets - outbound
	sb.WriteString(BuildSet("blocked_ips_out", "ipv4_addr", nil, blockedIPsOut))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_ranges_out", "ipv4_addr", []string{"interval", "auto-merge"}, blockedRangesOut))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_countries_out", "ipv4_addr", []string{"interval", "auto-merge"}, countryOut))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("blocked_asn_out", "ipv4_addr", []string{"interval", "auto-merge"}, asnOut))
	sb.WriteString("\n")
	// Sets - source allow-list (the "VIP list": accepted before any drop)
	sb.WriteString(BuildSet("allowed_ips", "ipv4_addr", nil, p.allowedIPs))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("allowed_ranges", "ipv4_addr", []string{"interval", "auto-merge"}, p.allowedRanges))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("allowed_countries", "ipv4_addr", []string{"interval", "auto-merge"}, p.allowedCountries))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("allowed_asn", "ipv4_addr", []string{"interval", "auto-merge"}, p.allowedASN))
	sb.WriteString("\n")
	// Sets - ports
	sb.WriteString(BuildSet("allowed_tcp_ports", "inet_service", nil, tcpPorts))
	sb.WriteString("\n")
	sb.WriteString(BuildSet("allowed_udp_ports", "inet_service", nil, udpPorts))
	sb.WriteString("\n")
	// Set - per-peer WAN block (drop only when traffic egresses the WAN iface)
	sb.WriteString(BuildSet("no_internet_peers", "ipv4_addr", nil, noInternetPeers))
	sb.WriteString("\n")

	// Input chain - traffic destined TO the server (check source address)
	inputRules := []string{
		"# Allow established connections",
		"ct state established,related accept",
		"",
		"# Allow loopback interface",
		"iif lo accept",
		"",
		"# Allow ICMPv6 (neighbour discovery) — required for IPv6 to function; harmless on",
		"# an IPv4-only panel and never a source-based leak.",
		"ip6 nexthdr icmpv6 accept",
		"",
	}
	// NOTE: IPv4 `ip protocol icmp accept` is intentionally emitted AFTER the block drops
	// (below), so a blocked IP/country/ASN can't even ping the server. Established/related
	// ICMP (incl. PMTUD errors) still rides the ct rule at the top of the chain.
	// Drop all inbound IPv6 arriving on the public interface. This panel is IPv4-only:
	// the blocklist/country sets are ipv4_addr, so an IPv6 packet to an open port would
	// otherwise be accepted unfiltered (the port rules below are protocol-agnostic).
	// Loopback (::1) and ICMPv6 neighbour discovery are already accepted above; the VPN
	// (wg0) and Headscale overlay (fd7a::) ride other interfaces, so scoping the drop to
	// the WAN NIC blocks only external IPv6 and leaves internal IPv6 intact.
	// NOTE: Docker-published container ports use their own DNAT/forward path and are NOT
	// governed by this chain — revisit this if the host ever gains real public IPv6.
	if wanIface != "" {
		inputRules = append(inputRules,
			"# Drop external IPv6 (IPv4-only panel)",
			"meta nfproto ipv6 iifname \""+SanitizeElement(wanIface)+"\" drop",
			"",
		)
	} else {
		// WAN NIC couldn't be detected — fail CLOSED rather than open: drop all other
		// inbound IPv6 unscoped. Loopback and ICMPv6 ND are accepted above, and the panel
		// is IPv4-only (no legitimate inbound IPv6-to-server path), so this closes the
		// leak (external IPv6 reaching an open port unfiltered) without losing anything.
		inputRules = append(inputRules,
			"# WAN NIC undetected — drop external IPv6 unscoped (fail closed, IPv4-only panel)",
			"meta nfproto ipv6 drop",
			"",
		)
	}
	inputRules = append(inputRules, allowAndSaddrDropRules()...)
	inputRules = append(inputRules,
		"",
		"# Allow ICMP/ping from non-blocked sources (after the drops, so a blocked",
		"# IP/country/ASN gets no response at all)",
		"ip protocol icmp accept",
		"",
		"# Allow specific ports",
		"tcp dport @allowed_tcp_ports accept",
		"udp dport @allowed_udp_ports accept",
		"",
		"# Log and drop everything else",
		`limit rate 5/minute log prefix "FIREWALL_DROP: " drop`,
	)
	sb.WriteString(BuildChain("input", "filter", "input", 0, "drop", inputRules))
	sb.WriteString("\n")

	// Forward chain - traffic routed THROUGH the server (VPN clients)
	// Needs both saddr (block bad sources) and daddr (block bad destinations)
	forwardRules := []string{
		"# Clamp TCP MSS to the path MTU so large packets always fit the tunnel.",
		"# Fixes slow VPN throughput (dropped oversized packets) without needing",
		"# to tune MTU on each client. Non-terminating: only rewrites SYN packets.",
		"tcp flags syn tcp option maxseg size set rt mtu",
		"",
		"# Allow established connections",
		"ct state established,related accept",
		"",
	}
	// Drop forwarded IPv6 heading to the internet. This panel is IPv4-only: the geo/ASN/
	// block-internet rules are all ipv4_addr, so without this a peer (or a block_internet
	// peer) reaches the internet over IPv6 and bypasses every egress control. Scoped to the
	// WAN NIC so intra-host/VPN IPv6 is untouched; skipped if the WAN NIC can't be detected
	// (same as the per-peer WAN block below — never emit an unscoped forward drop).
	if wanIface != "" {
		forwardRules = append(forwardRules,
			"# Drop forwarded IPv6 to the internet (IPv4-only egress controls)",
			"meta nfproto ipv6 oifname \""+SanitizeElement(wanIface)+"\" drop",
			"",
		)
	}
	forwardRules = append(forwardRules, allowAndSaddrDropRules()...)
	forwardRules = append(forwardRules,
		"",
		"# Drop traffic TO blocked destinations (daddr)",
		"ip daddr @blocked_ips_out drop",
		"ip daddr @blocked_ranges_out drop",
		"ip daddr @blocked_countries_out drop",
		"ip daddr @blocked_asn_out drop",
	)
	// Per-peer WAN egress block. Skip silently if WAN couldn't be detected — emitting
	// the rule without oifname would block *all* peer traffic, including peer↔peer.
	if wanIface != "" && len(noInternetPeers) > 0 {
		forwardRules = append(forwardRules,
			"",
			"# Drop WAN-bound traffic from flagged peers (per-peer no-internet)",
			"ip saddr @no_internet_peers oifname \""+SanitizeElement(wanIface)+"\" drop",
		)
	}
	forwardRules = append(forwardRules,
		"",
		"# Log and allow VPN traffic",
		`iifname "wg0" ct state new log prefix "VPN_TRAFFIC: " accept`,
		`oifname "wg0" accept`,
		`iifname "tailscale0" ct state new log prefix "VPN_TRAFFIC: " accept`,
		`oifname "tailscale0" accept`,
	)
	sb.WriteString(BuildChain("forward", "filter", "forward", -1, "accept", forwardRules))
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
		"ip daddr @blocked_asn_out drop",
	}))

	sb.WriteString(TableFooter())

	return sb.String()
}
