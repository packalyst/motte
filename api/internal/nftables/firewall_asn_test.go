package nftables

import (
	"regexp"
	"strings"
	"testing"
)

// TestBuildScriptSetsAreDefined guards the cardinal nftables rule: every set
// referenced by a rule (@name) must be defined in the same table, or the whole
// ruleset fails to load and the firewall wedges. This is the main risk of adding
// the ASN sets, so it's checked explicitly.
func TestBuildScriptSetsAreDefined(t *testing.T) {
	ft := &FirewallTable{} // buildScript uses only its arguments, not t
	script := ft.buildScript(scriptParams{
		blockedIPsIn: []string{"1.1.1.1"}, blockedIPsOut: []string{"2.2.2.2"},
		blockedRangesIn: []string{"3.3.3.0/24"}, blockedRangesOut: []string{"4.4.4.0/24"},
		tcpPorts: []string{"22"}, udpPorts: []string{"51820"},
		countryIn: []string{"5.5.0.0/16"}, countryOut: []string{"6.6.0.0/16"},
		asnIn: []string{"7.7.7.0/24"}, asnOut: []string{"8.8.8.0/24"},
		allowedIPs: []string{"9.9.9.9"}, allowedRanges: []string{"11.11.0.0/16"},
		allowedCountries: []string{"12.12.0.0/16"}, allowedASN: []string{"13.13.13.0/24"},
		noInternetPeers: []string{"10.8.0.9"}, wanIface: "eth0",
	})

	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`set (\w+) \{`).FindAllStringSubmatch(script, -1) {
		defined[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`@(\w+)`).FindAllStringSubmatch(script, -1) {
		if !defined[m[1]] {
			t.Errorf("rule references @%s but no such set is defined — would wedge the ruleset", m[1])
		}
	}

	// The ASN + allow sets and their rules must be present.
	for _, want := range []string{
		"set blocked_asn {",
		"set blocked_asn_out {",
		"ip daddr @blocked_asn_out drop",
		"set allowed_ips {",
		"set allowed_ranges {",
		"set allowed_countries {",
		"set allowed_asn {",
		// A country/ASN allow exempts its IPs from the geo/ASN drop but stays port-gated.
		"ip saddr @blocked_asn ip saddr != @allowed_countries ip saddr != @allowed_asn drop",
		"ip saddr @blocked_countries ip saddr != @allowed_countries ip saddr != @allowed_asn drop",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("generated script missing %q", want)
		}
	}

	// Security regression guard: a whole-country/ASN allow must NEVER become an
	// unconditional all-port accept in a default-drop chain (would expose SSH/admin to
	// an entire country). Only explicit @allowed_ips/@allowed_ranges may full-accept.
	for _, forbidden := range []string{
		"ip saddr @allowed_countries accept",
		"ip saddr @allowed_asn accept",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("generated script must NOT contain unconditional country/ASN accept %q", forbidden)
		}
	}
}

// TestVPNACLSkipsIPv6 guards against the critical wedge: an IPv6 address anywhere in the
// vpn_acl inputs must be skipped, never emitted into an IPv4-only `ip saddr/daddr` matcher
// (which would make the atomic table fail to load and silently drop all peer isolation).
func TestVPNACLSkipsIPv6(t *testing.T) {
	at := &VPNACLTable{}
	clients := map[int64]vpnClient{
		1: {ID: 1, Name: "v4peer", IP: "10.8.0.2", Type: "wireguard", Policy: "allow_all"},
		2: {ID: 2, Name: "v6peer", IP: "fd7a:115c:a1e0::5", Type: "headscale", Policy: "allow_all"},
	}
	vips := []aclVirtualIP{
		{IP: "10.8.128.5", Restricted: true, Quarantine: true, Allowed: []string{"10.8.0.2", "fd7a:115c:a1e0::9"}},
		{IP: "fd7a:115c:a1e0::7", Restricted: false}, // IPv6 vip must be skipped
	}
	script := at.buildScript(clients, nil, vips, "10.8.0.0/16", "100.64.0.0/16", "10.8.0.1")
	for _, bad := range []string{"fd7a:115c:a1e0::5", "fd7a:115c:a1e0::7", "fd7a:115c:a1e0::9"} {
		if strings.Contains(script, bad) {
			t.Errorf("IPv6 address %q leaked into the IPv4-only vpn_acl script — would wedge the table", bad)
		}
	}
	if !strings.Contains(script, "10.8.0.2") || !strings.Contains(script, "10.8.128.5") {
		t.Error("IPv4 peer/vip rules missing — over-filtered")
	}
}

// TestVPNACLAllowAllExcludesVips guards that an allow_all peer's range-wide accepts carve
// out the @vips set, so a restricted vip stays unreachable and a quarantined vip can't
// ride the accept out to the allow_all peer.
func TestVPNACLAllowAllExcludesVips(t *testing.T) {
	at := &VPNACLTable{}
	clients := map[int64]vpnClient{
		1: {ID: 1, Name: "trusted", IP: "10.8.0.9", Type: "wireguard", Policy: "allow_all"},
	}
	vips := []aclVirtualIP{
		{IP: "10.8.128.5", Restricted: true, Quarantine: true, Allowed: []string{"10.8.0.2"}},
	}
	script := at.buildScript(clients, nil, vips, "10.8.0.0/16", "100.64.0.0/16", "10.8.0.1")
	if !strings.Contains(script, "set vips {") || !strings.Contains(script, "10.8.128.5") {
		t.Fatal("vips set not defined/populated")
	}
	if !strings.Contains(script, "ip saddr 10.8.0.9 ip daddr 10.8.0.0/16 ip daddr != @vips accept") {
		t.Error("allow_all outbound does not exclude @vips — restricted vip would be reachable")
	}
	if !strings.Contains(script, "ip saddr 10.8.0.0/16 ip saddr != @vips ip daddr 10.8.0.9 accept") {
		t.Error("allow_all inbound does not exclude @vips — quarantined vip could initiate out")
	}
}

// TestFirewallFailsClosedOnUnknownWAN guards that when the WAN NIC can't be detected the
// input chain drops external IPv6 UNSCOPED (fail closed), rather than skipping the drop and
// letting IPv6 reach open ports unfiltered.
func TestFirewallFailsClosedOnUnknownWAN(t *testing.T) {
	ft := &FirewallTable{}
	noWAN := ft.buildScript(scriptParams{tcpPorts: []string{"22"}, wanIface: ""})
	if !strings.Contains(noWAN, "meta nfproto ipv6 drop") {
		t.Error("WAN undetected must emit an unscoped IPv6 drop (fail closed)")
	}
	withWAN := ft.buildScript(scriptParams{tcpPorts: []string{"22"}, wanIface: "eth0"})
	if !strings.Contains(withWAN, `meta nfproto ipv6 iifname "eth0" drop`) {
		t.Error("with a WAN iface, the IPv6 drop must be scoped to it")
	}
	if strings.Contains(withWAN, "meta nfproto ipv6 drop") {
		t.Error("with a WAN iface, the drop must be scoped, not unscoped")
	}
}

// TestBuildSetAutoMerge guards the interval-wedge fix: auto-merge must be emitted as its
// own set statement (not a `flags` keyword, which nft rejects), and only alongside
// `flags interval`. Without it, overlapping interval elements wedge the atomic reload.
func TestBuildSetAutoMerge(t *testing.T) {
	s := BuildSet("x", "ipv4_addr", []string{"interval", "auto-merge"}, []string{"1.0.0.0/8", "1.1.0.0/16"})
	if !strings.Contains(s, "flags interval\n") {
		t.Error("missing `flags interval`")
	}
	if !strings.Contains(s, "\n        auto-merge\n") {
		t.Error("auto-merge must be on its own line")
	}
	if strings.Contains(s, "interval, auto-merge") {
		t.Error("auto-merge must NOT be a flags keyword (nft rejects it)")
	}
	// A non-interval set must never get auto-merge, even if passed.
	if p := BuildSet("y", "ipv4_addr", []string{"auto-merge"}, []string{"1.2.3.4"}); strings.Contains(p, "auto-merge") {
		t.Error("auto-merge emitted without `flags interval`")
	}
}

// TestBuildScriptAllowBeforeDeny guards the security-critical ordering: in each
// chain the source allow-list (accept) must appear BEFORE the block-list (drop),
// otherwise a block would win over an intended allow-exception.
func TestBuildScriptAllowBeforeDeny(t *testing.T) {
	ft := &FirewallTable{}
	script := ft.buildScript(scriptParams{
		allowedIPs:   []string{"9.9.9.9"},
		blockedIPsIn: []string{"1.1.1.1"},
		wanIface:     "eth0",
	})

	// Split into the input and forward chains and check ordering within each.
	for _, chain := range []string{"chain input", "chain forward"} {
		start := strings.Index(script, chain)
		if start < 0 {
			t.Fatalf("missing %q", chain)
		}
		seg := script[start:]
		if end := strings.Index(seg[len(chain):], "chain "); end >= 0 {
			seg = seg[:len(chain)+end]
		}
		allow := strings.Index(seg, "ip saddr @allowed_ips accept")
		deny := strings.Index(seg, "ip saddr @blocked_ips drop")
		if allow < 0 || deny < 0 {
			t.Fatalf("%s: missing allow/deny rule (allow=%d deny=%d)", chain, allow, deny)
		}
		if allow > deny {
			t.Errorf("%s: allow rule (%d) must come BEFORE deny rule (%d)", chain, allow, deny)
		}
	}
}
