package nftables

import (
	"os"
	"testing"
)

// TestDumpScriptsForLint writes the generated firewall + vpn_acl rulesets to files so
// they can be syntax-checked with `nft -c`. Only runs when DUMP_NFT_DIR is set, so it's
// a no-op in normal test runs. Not a correctness assertion — a lint harness.
func TestDumpScriptsForLint(t *testing.T) {
	dir := os.Getenv("DUMP_NFT_DIR")
	if dir == "" {
		t.Skip("set DUMP_NFT_DIR to dump scripts for nft -c linting")
	}

	ft := &FirewallTable{}
	fw := ft.buildScript(scriptParams{
		blockedIPsIn: []string{"1.1.1.1"}, blockedIPsOut: []string{"2.2.2.2"},
		blockedRangesIn: []string{"3.3.3.0/24"}, blockedRangesOut: []string{"4.4.4.0/24"},
		tcpPorts: []string{"22", "443"}, udpPorts: []string{"51820"},
		countryIn: []string{"5.5.0.0/16"}, countryOut: []string{"6.6.0.0/16"},
		// Deliberately OVERLAPPING CIDRs (7.7.0.0/16 ⊃ 7.7.7.0/24): without the auto-merge
		// set flag, nft -f rejects these and wedges the whole table. With it, they merge.
		asnIn: []string{"7.7.0.0/16", "7.7.7.0/24"}, asnOut: []string{"8.8.8.0/24"},
		allowedIPs: []string{"9.9.9.9"}, allowedRanges: []string{"11.11.0.0/16"},
		allowedCountries: []string{"12.12.0.0/16"}, allowedASN: []string{"13.13.13.0/24"},
		noInternetPeers: []string{"10.8.0.9"}, wanIface: "eth0",
	})
	if err := os.WriteFile(dir+"/firewall.nft", []byte(fw), 0o644); err != nil {
		t.Fatal(err)
	}

	// vpn_acl needs a DB; buildScript takes its data directly, so drive it with fixtures.
	at := &VPNACLTable{}
	clients := map[int64]vpnClient{
		1: {ID: 1, Name: "phone", IP: "10.8.0.2", Type: "wireguard", Policy: "default"},
		2: {ID: 2, Name: "laptop", IP: "10.8.0.3", Type: "wireguard", Policy: "allow_all"},
		3: {ID: 3, Name: "iot", IP: "10.8.0.4", Type: "wireguard", Policy: "block_all"},
		4: {ID: 4, Name: "hs-v6", IP: "fd7a:115c:a1e0::5", Type: "headscale", Policy: "allow_all"}, // IPv6 must be skipped, not wedge
	}
	rules := []aclRule{{SourceID: 1, TargetID: 2, Bidirectional: true}}
	vips := []aclVirtualIP{
		{IP: "10.8.128.5", Restricted: true, Quarantine: true, Allowed: []string{"10.8.0.2"}},
		{IP: "10.8.128.6", Restricted: false, Quarantine: false},
		{IP: "fd7a:115c:a1e0::7", Restricted: false}, // IPv6 vip must be skipped
	}
	// WG range is /16 so the upper-half vips (10.8.128.x) sit INSIDE it (that's what
	// makes the catch-all wg->wg drop cover restricted vips). Headscale range is the
	// real IPv4 value; vpn_acl only ever reads the IPv4 HEADSCALE_IP_RANGE.
	acl := at.buildScript(clients, rules, vips, "10.8.0.0/16", "100.64.0.0/16", "10.8.0.1")
	if err := os.WriteFile(dir+"/vpn_acl.nft", []byte(acl), 0o644); err != nil {
		t.Fatal(err)
	}
}
