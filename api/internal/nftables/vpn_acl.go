package nftables

import (
	"fmt"
	"log"
	"strings"

	"api/internal/database"
	"api/internal/helper"
)

// VPNACLTable builds the inet vpn_acl table
type VPNACLTable struct {
	db *database.DB
}

// NewVPNACLTable creates a new VPN ACL table builder
func NewVPNACLTable(db *database.DB) *VPNACLTable {
	return &VPNACLTable{db: db}
}

func (t *VPNACLTable) Name() string   { return "wgadmin_vpn_acl" }
func (t *VPNACLTable) Family() string { return "inet" }
func (t *VPNACLTable) Priority() int  { return 20 }

// Build generates the nftables script for VPN ACL
func (t *VPNACLTable) Build() (string, error) {
	wgIPRange := helper.GetEnvOptional("WG_IP_RANGE", "")
	hsIPRange := helper.GetEnvOptional("HEADSCALE_IP_RANGE", "")
	serverIP := helper.GetEnvOptional("SERVER_IP", "")

	// Load clients
	clients, err := t.loadClients()
	if err != nil {
		return "", err
	}

	// Load ACL rules
	rules, err := t.loadRules()
	if err != nil {
		return "", err
	}

	// Load virtual IPs + their allow-lists
	vips, err := t.loadVirtualIPs(clients)
	if err != nil {
		return "", err
	}

	return t.buildScript(clients, rules, vips, wgIPRange, hsIPRange, serverIP), nil
}

type vpnClient struct {
	ID     int64
	Name   string
	IP     string
	Type   string
	Policy string
}

type aclRule struct {
	SourceID      int64
	TargetID      int64
	Bidirectional bool
}

func (t *VPNACLTable) loadClients() (map[int64]vpnClient, error) {
	rows, err := t.db.Query(`SELECT id, name, ip, type, acl_policy FROM vpn_clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clients := make(map[int64]vpnClient)
	for rows.Next() {
		var c vpnClient
		if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Type, &c.Policy); err != nil {
			continue
		}
		clients[c.ID] = c
	}
	return clients, nil
}

func (t *VPNACLTable) loadRules() ([]aclRule, error) {
	rows, err := t.db.Query(`SELECT source_client_id, target_client_id, bidirectional FROM vpn_acl_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []aclRule
	for rows.Next() {
		var r aclRule
		if err := rows.Scan(&r.SourceID, &r.TargetID, &r.Bidirectional); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// aclVirtualIP is a virtual IP plus the source peer IPs allowed to reach it.
type aclVirtualIP struct {
	IP         string
	Restricted bool
	Quarantine bool     // may be reached, but can't initiate to other peers
	Allowed    []string // allowed source peer IPs (only meaningful when Restricted)
}

// loadVirtualIPs loads virtual IPs and, for restricted ones, the source peer IPs
// allowed to reach them. The outer result is drained before the per-vip allow-list
// queries run, so no cursor is held open across a nested query.
func (t *VPNACLTable) loadVirtualIPs(clients map[int64]vpnClient) ([]aclVirtualIP, error) {
	rows, err := t.db.Query(`SELECT id, ip, restricted, quarantine FROM vpn_virtual_ips`)
	if err != nil {
		return nil, err
	}
	type row struct {
		id         int64
		ip         string
		restricted int
		quarantine int
	}
	var raw []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ip, &r.restricted, &r.quarantine); err != nil {
			continue
		}
		raw = append(raw, r)
	}
	rows.Close()

	out := make([]aclVirtualIP, 0, len(raw))
	for _, r := range raw {
		v := aclVirtualIP{IP: r.ip, Restricted: r.restricted == 1, Quarantine: r.quarantine == 1}
		if v.Restricted {
			arows, err := t.db.Query(`SELECT source_client_id FROM vpn_virtual_ip_acl WHERE virtual_ip_id = ?`, r.id)
			if err == nil {
				for arows.Next() {
					var cid int64
					if arows.Scan(&cid) == nil {
						if c, ok := clients[cid]; ok {
							v.Allowed = append(v.Allowed, c.IP)
						}
					}
				}
				arows.Close()
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func (t *VPNACLTable) buildScript(clients map[int64]vpnClient, rules []aclRule, vips []aclVirtualIP, wgIPRange, hsIPRange, serverIP string) string {
	var sb strings.Builder

	// Validate IP ranges before use
	if !ValidateIPv4OrCIDR(wgIPRange) {
		wgIPRange = ""
	}
	if !ValidateIPv4OrCIDR(hsIPRange) {
		hsIPRange = ""
	}
	if serverIP != "" && !ValidateIPv4OrCIDR(serverIP) {
		serverIP = ""
	}

	sb.WriteString("# VPN ACL nftables rules\n")
	sb.WriteString("# AUTO-GENERATED - DO NOT EDIT\n")
	if serverIP != "" {
		sb.WriteString(fmt.Sprintf("# Server: %s\n\n", SanitizeComment(serverIP)))
	}

	// Collect IPv4 vip addresses into a set so the allow_all blanket accepts can carve
	// them out — a vip must obey ONLY its own restricted/quarantine rules, never an
	// allow_all peer's range-wide accept. An empty set makes `!= @vips` always true, so
	// setups without vips behave exactly as before.
	var vipIPs []string
	for _, v := range vips {
		if ValidateIPv4OrCIDR(v.IP) {
			vipIPs = append(vipIPs, v.IP)
		}
	}

	// Delete existing table
	sb.WriteString("table inet wgadmin_vpn_acl\ndelete table inet wgadmin_vpn_acl\n\n")

	sb.WriteString("table inet wgadmin_vpn_acl {\n")
	sb.WriteString(BuildSet("vips", "ipv4_addr", nil, vipIPs))
	sb.WriteString("\n")
	sb.WriteString("    chain forward {\n")
	sb.WriteString("        type filter hook forward priority 0; policy accept;\n\n")
	sb.WriteString("        # Allow established/related (lets replies to inbound-initiated\n")
	sb.WriteString("        # flows through, including ICMP errors for PMTUD)\n")
	sb.WriteString("        ct state established,related accept\n\n")
	// There is deliberately NO blanket `ip protocol icmp accept` here. Placed above the
	// drops it let quarantined/block_all/restricted devices be pinged or ping out,
	// defeating isolation. ICMP is now governed by the same ACL as every other protocol:
	// allowed peer pairs (and open/allowed vips) get ICMP via their protocol-agnostic
	// accept rules below; replies ride ct established,related above; everything else is
	// caught by the drops. Isolated peers therefore cannot be pinged and cannot ping out.
	sb.WriteString("        # === VPN ACL Rules ===\n\n")

	// Handle block_all clients first - explicit drop before any accept
	for _, c := range clients {
		if !ValidateIPv4OrCIDR(c.IP) {
			continue
		}
		if c.Policy == helper.ACLPolicyBlockAll {
			safeName := SanitizeComment(c.Name)
			sb.WriteString(fmt.Sprintf("        # %s [block_all]\n", safeName))
			sb.WriteString(fmt.Sprintf("        ip saddr %s drop\n", c.IP))
			sb.WriteString(fmt.Sprintf("        ip daddr %s drop\n\n", c.IP))
		}
	}

	allowedPairs := make(map[string]bool)

	// Handle allow_all policy clients
	// allow_all = can reach everyone AND everyone can reach them
	for _, c := range clients {
		if !ValidateIPv4OrCIDR(c.IP) {
			continue
		}
		if c.Policy == helper.ACLPolicyAllowAll {
			safeName := SanitizeComment(c.Name)
			sb.WriteString(fmt.Sprintf("        # %s [allow_all] - outbound\n", safeName))
			if wgIPRange != "" {
				// != @vips: an allow_all peer must NOT auto-reach a vip; the vip's own
				// restricted/open rules decide instead. (vips live in the WG range.)
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s ip daddr != @vips accept\n", c.IP, wgIPRange))
			}
			if hsIPRange != "" {
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s accept\n", c.IP, hsIPRange))
			}
			sb.WriteString(fmt.Sprintf("        # %s [allow_all] - inbound\n", safeName))
			if wgIPRange != "" {
				// != @vips: a quarantined vip must NOT ride this accept out to the peer;
				// its quarantine drop governs instead.
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip saddr != @vips ip daddr %s accept\n", wgIPRange, c.IP))
			}
			if hsIPRange != "" {
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s accept\n", hsIPRange, c.IP))
			}
			sb.WriteString("\n")
		}
	}

	// Process explicit rules
	for _, rule := range rules {
		src, srcExists := clients[rule.SourceID]
		dst, dstExists := clients[rule.TargetID]
		if !srcExists || !dstExists {
			continue
		}

		if !ValidateIPv4OrCIDR(src.IP) || !ValidateIPv4OrCIDR(dst.IP) {
			continue
		}

		// Skip if either has block_all (isolated)
		if src.Policy == helper.ACLPolicyBlockAll || dst.Policy == helper.ACLPolicyBlockAll {
			continue
		}

		// Generate source→target rule
		// Skip if src has allow_all (covered by blanket outbound)
		// Skip if dst has allow_all (covered by blanket inbound)
		if src.Policy != helper.ACLPolicyAllowAll && dst.Policy != helper.ACLPolicyAllowAll {
			key := fmt.Sprintf("%s->%s", src.IP, dst.IP)
			if !allowedPairs[key] {
				sb.WriteString(fmt.Sprintf("        # %s -> %s\n", SanitizeComment(src.Name), SanitizeComment(dst.Name)))
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s accept\n\n", src.IP, dst.IP))
				allowedPairs[key] = true
			}
		}

		// Generate target→source rule if bidirectional
		// Skip if dst has allow_all (covered by blanket outbound)
		// Skip if src has allow_all (covered by blanket inbound)
		if rule.Bidirectional && dst.Policy != helper.ACLPolicyAllowAll && src.Policy != helper.ACLPolicyAllowAll {
			reverseKey := fmt.Sprintf("%s->%s", dst.IP, src.IP)
			if !allowedPairs[reverseKey] {
				sb.WriteString(fmt.Sprintf("        # %s -> %s [bi]\n", SanitizeComment(dst.Name), SanitizeComment(src.Name)))
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s accept\n\n", dst.IP, src.IP))
				allowedPairs[reverseKey] = true
			}
		}
	}

	// === Virtual IP access ===
	// Virtual IPs sit inside the WG range, so the catch-all wg->wg drop below already
	// makes them unreachable by default. Emit accepts here (before that drop) to open
	// them: restricted -> only the listed source peers; open -> any peer. A restricted
	// vip with no allowed sources emits nothing and stays unreachable (secure default).
	sb.WriteString("        # === Virtual IPs ===\n")
	// Quarantine: the device may be reached but must not initiate to other peers.
	// Drops come before the accepts; ct established,related (top of chain) still lets
	// replies to an inbound connection through.
	for _, v := range vips {
		if !v.Quarantine || !ValidateIPv4OrCIDR(v.IP) {
			continue
		}
		if wgIPRange != "" {
			sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", v.IP, wgIPRange))
		}
		if hsIPRange != "" {
			sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", v.IP, hsIPRange))
		}
	}
	for _, v := range vips {
		if !ValidateIPv4OrCIDR(v.IP) {
			continue
		}
		if v.Restricted {
			for _, src := range v.Allowed {
				if !ValidateIPv4OrCIDR(src) {
					continue
				}
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s accept\n", src, v.IP))
			}
		} else {
			sb.WriteString(fmt.Sprintf("        ip daddr %s accept\n", v.IP))
		}
	}
	sb.WriteString("\n")

	// Drop unallowed VPN-to-VPN traffic (default-deny backstop, symmetric across both
	// ranges: wg<->wg, wg<->hs, hs<->hs). Explicit allow rules and allow_all peers are
	// emitted earlier in the chain, so only *unallowed* peer-to-peer traffic is dropped.
	sb.WriteString("        # Drop unallowed VPN traffic\n")
	if wgIPRange != "" && hsIPRange != "" {
		sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", wgIPRange, hsIPRange))
		sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", hsIPRange, wgIPRange))
	}
	if wgIPRange != "" {
		sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", wgIPRange, wgIPRange))
	}
	if hsIPRange != "" {
		sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", hsIPRange, hsIPRange))
	}

	// FAIL CLOSED when a VPN range is missing/invalid. Without it the IP-based catch-all
	// above can't be emitted, and the chain's policy is `accept` — so peers would reach each
	// other freely (isolation, restricted/quarantine vips all void). Fall back to an
	// interface-scoped drop of same-interface traffic (peer→peer enters AND leaves the VPN
	// NIC; internet-bound leaves the WAN NIC, so it's unaffected). Uses the wg0/tailscale0
	// names the firewall table already assumes. Established/related + explicit accepts are
	// emitted earlier, so allowed pairs still work; everything else peer↔peer is denied.
	if wgIPRange == "" {
		// Warn only when WireGuard peers actually exist (a Headscale-only deployment
		// legitimately has no WG range — the fallback drop is then just harmless, since
		// there's no wg0 traffic).
		for _, c := range clients {
			if c.Type == "wireguard" {
				log.Printf("nftables/vpn_acl: WG_IP_RANGE missing/invalid but WireGuard peers exist — falling back to interface isolation (wg0). Set a valid IPv4 WG_IP_RANGE to restore full peer/vip isolation.")
				break
			}
		}
		sb.WriteString("        # WG_IP_RANGE missing/invalid — interface fail-closed for WireGuard peers\n")
		sb.WriteString("        iifname \"wg0\" oifname \"wg0\" drop\n")
	}
	if hsIPRange == "" {
		sb.WriteString("        # HEADSCALE_IP_RANGE missing/invalid — interface fail-closed for Headscale peers\n")
		sb.WriteString("        iifname \"tailscale0\" oifname \"tailscale0\" drop\n")
	}

	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	return sb.String()
}
