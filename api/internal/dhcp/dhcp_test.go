package dhcp

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// dnsmasqConfPath must never return a path outside dnsmasqConfDir, no matter the interface value
// (defense-in-depth against a tampered/unvalidated DB value feeding a privileged file write).
func TestDnsmasqConfPath(t *testing.T) {
	ok := []string{"ens19", "eth0", "eth0.100", "br-lan", "vlan_5"}
	for _, iface := range ok {
		p, err := dnsmasqConfPath(iface)
		if err != nil {
			t.Errorf("dnsmasqConfPath(%q) unexpected error: %v", iface, err)
			continue
		}
		if want := "/dhcp-conf/motte-" + iface + ".conf"; p != want {
			t.Errorf("dnsmasqConfPath(%q) = %q, want %q", iface, p, want)
		}
	}
	// Anything that could escape the dir (a separator) or is otherwise invalid must fail closed.
	bad := []string{"", "../../etc/passwd", "a/b", "/etc/x", "name with space", strings.Repeat("x", 16)}
	for _, iface := range bad {
		if p, err := dnsmasqConfPath(iface); err == nil {
			t.Errorf("dnsmasqConfPath(%q) = %q, want error", iface, p)
		}
	}
}

// suggestSubnets must never offer a subnet that overlaps the VPN ranges or an existing managed
// network — the whole point is that a suggestion is safe by construction.
func TestSuggestSubnets(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.20.20.0/24")
	t.Setenv("HEADSCALE_IP_RANGE", "")
	others := []Network{{CIDR: "10.30.30.0/24"}}

	got := suggestSubnets(others, 6)
	if len(got) == 0 {
		t.Fatal("expected at least one suggestion")
	}
	if len(got) > 6 {
		t.Fatalf("must respect max=6, got %d", len(got))
	}
	for _, s := range got {
		if s.CIDR == "10.20.20.0/24" {
			t.Errorf("suggested the WG range %s", s.CIDR)
		}
		if s.CIDR == "10.30.30.0/24" {
			t.Errorf("suggested an existing managed network %s", s.CIDR)
		}
		if !strings.HasSuffix(s.GatewayIP, ".1") {
			t.Errorf("gateway should be .1, got %s", s.GatewayIP)
		}
		// Every suggestion must survive the real validator.
		n := &Network{Iface: "ens99", CIDR: s.CIDR, GatewayIP: s.GatewayIP,
			PoolStart: s.PoolStart, PoolEnd: s.PoolEnd, LeaseSecs: 43200, Domain: "lan", Mode: "approve"}
		if err := validateAddressing(n, others); err != nil {
			t.Errorf("suggested %s failed validateAddressing: %v", s.CIDR, err)
		}
	}
}

func baseNet() *Network {
	return &Network{
		Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1",
		PoolStart: "10.20.20.50", PoolEnd: "10.20.20.200",
		LeaseSecs: 43200, Domain: "lan", Mode: "approve", Enabled: true,
	}
}

func TestValidateAddressing(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Network)
		wantErr bool
	}{
		{"valid", func(n *Network) {}, false},
		{"public subnet rejected", func(n *Network) {
			n.CIDR = "8.8.8.0/24"
			n.GatewayIP = "8.8.8.1"
			n.PoolStart = "8.8.8.50"
			n.PoolEnd = "8.8.8.200"
		}, true},
		// Starts in RFC1918 but spills into public space (11/8, 192.169/16).
		{"subnet spilling out of 10/8 rejected", func(n *Network) { n.CIDR = "10.0.0.0/7" }, true},
		{"subnet spilling out of 192.168/16 rejected", func(n *Network) {
			n.CIDR = "192.168.0.0/15"
			n.GatewayIP = "192.168.0.1"
			n.PoolStart = "192.168.0.50"
			n.PoolEnd = "192.168.0.200"
		}, true},
		{"gateway outside subnet", func(n *Network) { n.GatewayIP = "10.20.21.1" }, true},
		{"pool includes gateway", func(n *Network) { n.PoolStart = "10.20.20.1" }, true},
		{"pool end before start", func(n *Network) { n.PoolStart = "10.20.20.200"; n.PoolEnd = "10.20.20.50" }, true},
		{"gateway not in pool is fine", func(n *Network) { n.GatewayIP = "10.20.20.254" }, false},
		{"lease too short", func(n *Network) { n.LeaseSecs = 10 }, true},
		{"bad mode", func(n *Network) { n.Mode = "whatever" }, true},
		{"subnet too small", func(n *Network) { n.CIDR = "10.20.20.0/31" }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := baseNet()
			c.mutate(n)
			err := validateAddressing(n, nil)
			if (err != nil) != c.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestValidateAddressingOverlap(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.20.20.0/24")
	if err := validateAddressing(baseNet(), nil); err == nil {
		t.Fatal("expected overlap with WG_IP_RANGE to be rejected")
	}

	other := Network{Iface: "ens20", CIDR: "10.20.20.0/24"}
	t.Setenv("WG_IP_RANGE", "")
	n := baseNet()
	n.Iface = "ens19"
	if err := validateAddressing(n, []Network{other}); err == nil {
		t.Fatal("expected overlap with another managed net to be rejected")
	}
}

func TestRenderNetplan(t *testing.T) {
	got, err := renderNetplan(baseNet())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"ens19":`, "dhcp4: false", `"10.20.20.1/24"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("netplan drop-in missing %q:\n%s", want, got)
		}
	}
}

func TestRenderDnsmasqConf(t *testing.T) {
	n := baseNet()
	res := []Client{{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.20.20.50", Name: "cam 1", Approved: true}}
	got := renderDnsmasqConf(n, res, []string{"02:00:00:00:00:09"})
	// port=0 is a GLOBAL that lives ONLY in the base conf — repeating it here makes dnsmasq
	// crash-loop with "illegal repeated keyword". (Regression guard, 2026-10-18.)
	if strings.Contains(got, "port=0") {
		t.Fatalf("per-network conf must not repeat the base global port=0:\n%s", got)
	}
	for _, want := range []string{
		"interface=ens19",
		"dhcp-range=10.20.20.50,10.20.20.200,255.255.255.0,43200s",
		"dhcp-option=3,10.20.20.1",
		"dhcp-host=aa:bb:cc:dd:ee:ff,10.20.20.50,cam-1", // reservation pins a stable IP, name sanitized
		"dhcp-host=02:00:00:00:00:09,ignore",            // a blocked device gets no address
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("dnsmasq conf missing %q:\n%s", want, got)
		}
	}
	// Approval is enforced by the firewall now, not by withholding leases — the conf carries no MAC
	// gating in either mode (no dhcp-ignore, no set:known tag).
	if strings.Contains(got, "dhcp-ignore") || strings.Contains(got, "set:known") {
		t.Fatalf("approve mode must not gate leases in dnsmasq (firewall is the gate):\n%s", got)
	}

	n.Mode = "auto"
	got = renderDnsmasqConf(n, res, nil)
	if strings.Contains(got, "dhcp-ignore") || strings.Contains(got, "set:known") {
		t.Fatalf("auto mode should not gate unknown clients:\n%s", got)
	}
}

// testPrivateRanges mirrors privateReachRanges() output with synthetic VPN ranges, so the renderer
// tests don't depend on the host environment.
var testPrivateRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "10.8.0.0/16", "100.64.0.0/10"}

// TestReachabilityPerDevice checks the per-device gates: access opens only the one device to only
// the granted VPN client, internet is per device behind the leak guard, a blocked MAC is dropped
// before anything else (including already-open connections and traffic to the box), and the
// subnet stays default-denied.
func TestReachabilityPerDevice(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Mode: "approve", Enabled: true}}
	pol := map[int64]netPolicy{1: {
		Devices: []devicePolicy{
			{IP: "10.20.20.55", MAC: "02:00:00:00:00:55", Allowed: []vpnGrant{{IP: "10.8.0.2", Both: true}}, Internet: true}, // camera: one client both ways, internet
			{IP: "10.20.20.66", MAC: "02:00:00:00:00:66"},                                                                    // printer: nobody, no internet
		},
		Blocked: []string{"02:00:00:00:00:09"},
	}}
	got := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{})
	for _, want := range []string{
		`ip saddr 10.8.0.2 ip daddr 10.20.20.55 accept`,                                               // granted client → that device
		`iifname "ens19" ether saddr 02:00:00:00:00:55 ip saddr 10.20.20.55 ip daddr 10.8.0.2 accept`, // and back, from its MAC only
		`iifname "ens19" ether saddr 02:00:00:00:00:55 ip saddr 10.20.20.55 oifname "eth0" accept`,    // its internet, from its MAC only
		`ip saddr 10.20.20.0/24 ip daddr @private_ranges ip daddr != 10.20.20.0/24 drop`,              // leak guard
		`ip saddr 10.20.20.0/24 oifname "eth0" masquerade`,                                            // NAT for the segment
		`iifname "ens19" ether saddr 02:00:00:00:00:09 drop`,                                          // blocked by MAC
		`ip daddr 10.20.20.0/24 drop`,                                                                 // default-deny
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	// The printer is reachable by nobody and has no internet.
	if strings.Contains(got, "daddr 10.20.20.66 accept") || strings.Contains(got, `saddr 10.20.20.66 oifname`) {
		t.Fatalf("a device without grants must stay closed:\n%s", got)
	}
	// Access is never granted to the whole subnet.
	if strings.Contains(got, "daddr 10.20.20.0/24 accept") {
		t.Fatalf("must not accept to the whole subnet:\n%s", got)
	}
	// Order: blocked drop before the established/related accept; leak guard before the WAN accept.
	at := func(sub string) int { return strings.Index(got, sub) }
	if at(`ether saddr 02:00:00:00:00:09 drop`) > at(`ct state established,related accept`) {
		t.Fatalf("blocked drop must come before the established accept:\n%s", got)
	}
	if at(`@private_ranges`+" ip daddr != 10.20.20.0/24 drop") > at(`ip saddr 10.20.20.55 oifname "eth0" accept`) {
		t.Fatalf("leak guard must come before the internet accept:\n%s", got)
	}
	// The box itself: the blocked MAC is dropped first; then any device gets DHCP and DNS, approved
	// devices (IP + MAC) get the rest, and everything else from the LAN is dropped — a device still
	// waiting for approval can't reach SSH or the panel API.
	inChain := got[at("chain input"):at("chain postrouting")]
	inOrder := []string{
		`iifname "ens19" ether saddr 02:00:00:00:00:09 drop`,
		`iifname "ens19" udp dport 67 accept`,
		`iifname "ens19" meta l4proto { tcp, udp } th dport 53 accept`,
		`iifname "ens19" ether saddr 02:00:00:00:00:55 ip saddr 10.20.20.55 accept`,
		`iifname "ens19" ether saddr 02:00:00:00:00:66 ip saddr 10.20.20.66 accept`,
		`iifname "ens19" drop`,
	}
	last := -1
	for _, rule := range inOrder {
		i := strings.Index(inChain, rule)
		if i < 0 || i < last {
			t.Fatalf("input chain must have, in order, %q:\n%s", rule, inChain)
		}
		last = i
	}
	// No rule lets the device's IP through without its MAC (a copied IP gets nothing).
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "saddr 10.20.20.55") && strings.Contains(line, "accept") && !strings.Contains(line, "ether saddr 02:00:00:00:00:55") {
			t.Fatalf("a rule accepts the device's IP without its MAC: %q", line)
		}
	}

	// No device with internet → no WAN path or NAT at all.
	pol[1] = netPolicy{Devices: []devicePolicy{{IP: "10.20.20.55", MAC: "02:00:00:00:00:55", Allowed: []vpnGrant{{IP: "10.8.0.2"}}}}}
	none := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{})
	if strings.Contains(none, "oifname") {
		t.Fatalf("no device has internet, so nothing may route out:\n%s", none)
	}

	// No approved devices → nothing forwardable.
	empty := renderReachability(nets, map[int64]netPolicy{}, "eth0", testPrivateRanges, routeOrigin{})
	if fwd := empty[strings.Index(empty, "chain forward"):strings.Index(empty, "chain input")]; strings.Count(fwd, " accept\n") != 1 { // only the ct accept
		t.Fatalf("with no devices, only the established accept may exist in forward:\n%s", empty)
	}

	// Invalid values are never emitted.
	bad := map[int64]netPolicy{1: {Devices: []devicePolicy{
		{IP: "not-an-ip", MAC: "02:00:00:00:00:01", Allowed: []vpnGrant{{IP: "1.2.3.4; flush ruleset", Both: true}}, Internet: true},
		{IP: "10.20.20.77", MAC: "02:00:00:00:00:77; flush ruleset", Internet: true},
		{IP: "10.20.20.78", MAC: "02:00:00:00:00:78", VPNIP: "10.8.128.9; flush ruleset", Allowed: []vpnGrant{{IP: "10.8.0.2", Both: true}}},
	}, Blocked: []string{"zz:zz"}}}
	if out := renderReachability(nets, bad, "eth0", testPrivateRanges, routeOrigin{}); strings.Contains(out, "flush") || strings.Contains(out, "zz:zz") || strings.Contains(out, "not-an-ip") || strings.Contains(out, "10.20.20.77") {
		t.Fatalf("invalid values leaked into the ruleset:\n%s", out)
	}
}

func TestNetmaskOf(t *testing.T) {
	for cidr, want := range map[string]string{
		"10.20.20.0/24":  "255.255.255.0",
		"10.0.0.0/16":    "255.255.0.0",
		"10.20.20.0/30":  "255.255.255.252",
		"192.168.1.0/25": "255.255.255.128",
	} {
		if got := netmaskOf(cidr); got != want {
			t.Errorf("netmaskOf(%s)=%s, want %s", cidr, got, want)
		}
	}
}

func TestSanitizeDHCPName(t *testing.T) {
	for in, want := range map[string]string{
		"cam 1":        "cam-1",
		"My_Laptop":    "my-laptop",
		"bad;rm -rf /": "badrm--rf",
		"":             "",
	} {
		if got := sanitizeDHCPName(in); got != want {
			t.Errorf("sanitizeDHCPName(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestValidMAC(t *testing.T) {
	ok := []string{"aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"}
	bad := []string{"aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee", "notamac", ""}
	for _, m := range ok {
		if !validMAC(m) {
			t.Errorf("validMAC(%q) = false, want true", m)
		}
	}
	for _, m := range bad {
		if validMAC(m) {
			t.Errorf("validMAC(%q) = true, want false", m)
		}
	}
}

// TestReachabilityNftSyntax renders the reachability table and runs the real `nft -c` against
// it, so the inet-table + nat-postrouting syntax is verified by nftables itself. Skipped where
// nft isn't available or can't run (e.g. no netlink in a restricted CI).
func TestReachabilityNftSyntax(t *testing.T) {
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not available")
	}
	nets := []Network{
		{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true, NATEnabled: true},
		{ID: 2, Iface: "ens20", CIDR: "192.168.50.0/24", GatewayIP: "192.168.50.1", Enabled: true, NATEnabled: false},
		{ID: 3, Iface: "ens21", CIDR: "172.16.0.0/24", GatewayIP: "172.16.0.1", Enabled: false}, // disabled → skipped
	}
	pol := map[int64]netPolicy{
		1: {Devices: []devicePolicy{{IP: "10.20.20.55", MAC: "02:00:00:00:00:55", VPNIP: "10.8.128.5",
			Allowed: []vpnGrant{{IP: "10.8.0.2", Both: true}, {IP: "10.8.0.3"}}, Internet: true, Routes: []int{80, 443}},
			{IP: "10.20.20.56", MAC: "02:00:00:00:00:56", VPNIP: "10.8.128.6", Routes: []int{8080}}},
			Blocked: []string{"02:00:00:00:00:09"}},
		2: {Devices: []devicePolicy{{IP: "192.168.50.20", MAC: "02:00:00:00:00:20"}}},
	}
	script := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{Iface: "br-0123456789ab", IP: "172.18.0.2"})

	// Disabled network must not appear; NAT-off network must not get a masquerade. Check the
	// disabled net's specific /24 (not the bare prefix — 172.16.0.0/12 is in the private_ranges set).
	if strings.Contains(script, "172.16.0.0/24") {
		t.Fatalf("disabled network leaked into ruleset:\n%s", script)
	}
	if strings.Contains(script, "192.168.50.0/24 oifname") || strings.Contains(script, "192.168.50.20 oifname") {
		t.Fatalf("a network with no internet devices got an internet-out path:\n%s", script)
	}

	f, err := os.CreateTemp(t.TempDir(), "dhcp-*.nft")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(script); err != nil {
		t.Fatal(err)
	}
	f.Close()
	out, err := exec.Command(nftPath, "-c", "-f", f.Name()).CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "permission") || strings.Contains(s, "not permitted") || strings.Contains(s, "netlink") {
			t.Skipf("nft -c can't run in this environment: %s", strings.TrimSpace(s))
		}
		t.Fatalf("nft rejected the generated ruleset: %v\n%s\n---\n%s", err, strings.TrimSpace(s), script)
	}
}

func TestSanitizeLeaseName(t *testing.T) {
	cases := map[string]string{
		"laptop":        "laptop",
		"  host-1  ":    "host-1",
		"*":             "",
		"":              "",
		"bad\x00name":   "badname",
		"tab\tin\tname": "tabinname",
	}
	for in, want := range cases {
		if got := sanitizeLeaseName(in); got != want {
			t.Errorf("sanitizeLeaseName(%q) = %q, want %q", in, got, want)
		}
	}
}
