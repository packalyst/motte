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
