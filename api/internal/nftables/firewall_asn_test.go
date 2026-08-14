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
	script := ft.buildScript(
		[]string{"1.1.1.1"},    // blockedIPsIn
		[]string{"2.2.2.2"},    // blockedIPsOut
		[]string{"3.3.3.0/24"}, // blockedRangesIn
		[]string{"4.4.4.0/24"}, // blockedRangesOut
		[]string{"22"},         // tcpPorts
		[]string{"51820"},      // udpPorts
		[]string{"5.5.0.0/16"}, // countryIn
		[]string{"6.6.0.0/16"}, // countryOut
		[]string{"7.7.7.0/24"}, // asnIn
		[]string{"8.8.8.0/24"}, // asnOut
		[]string{"10.8.0.9"},   // noInternetPeers
		"eth0",                 // wanIface
	)

	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`set (\w+) \{`).FindAllStringSubmatch(script, -1) {
		defined[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`@(\w+)`).FindAllStringSubmatch(script, -1) {
		if !defined[m[1]] {
			t.Errorf("rule references @%s but no such set is defined — would wedge the ruleset", m[1])
		}
	}

	// The ASN sets and their drop rules must be present.
	for _, want := range []string{
		"set blocked_asn {",
		"set blocked_asn_out {",
		"ip saddr @blocked_asn drop",
		"ip daddr @blocked_asn_out drop",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("generated script missing %q", want)
		}
	}
}
