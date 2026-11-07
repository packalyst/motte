package dhcp

import (
	"os"
	"os/exec"
	"slices"
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
			{IP: "10.20.20.55", MAC: "02:00:00:00:00:55", Allowed: []vpnGrant{{IP: "10.8.0.2", Both: true}}, Internet: true, Out: portsOf("all")}, // camera: one client both ways, internet
			{IP: "10.20.20.66", MAC: "02:00:00:00:00:66"}, // printer: nobody, no internet
		},
		Blocked: []string{"02:00:00:00:00:09"},
	}}
	got := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{}, "")
	for _, want := range []string{
		`ip saddr 10.8.0.2 ip daddr 10.20.20.55 accept`,                                                                                                     // granted client → that device
		`iifname "ens19" ether saddr 02:00:00:00:00:55 ip saddr 10.20.20.55 ip daddr 10.8.0.2 accept`,                                                       // and back, from its MAC only
		`iifname "ens19" ether saddr 02:00:00:00:00:55 ip saddr 10.20.20.55 oifname "eth0" tcp dport { 22, 25, 53, 80, 443, 465, 587, 853, 993, 995 } drop`, // every port but the services
		`iifname "ens19" ether saddr 02:00:00:00:00:55 ip saddr 10.20.20.55 oifname "eth0" accept`,                                                          // its internet, from its MAC only
		`ip saddr 10.20.20.0/24 ip daddr @private_ranges ip daddr != 10.20.20.0/24 drop`,                                                                    // leak guard
		`ip saddr 10.20.20.55 oifname "eth0" masquerade`,                                                                                                    // NAT for that device only
		`iifname "ens19" ether saddr 02:00:00:00:00:09 drop`,                                                                                                // blocked by MAC
		`ip daddr 10.20.20.0/24 drop`, // default-deny
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
	none := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{}, "")
	if strings.Contains(none, `oifname "eth0"`) {
		t.Fatalf("no device has internet, so nothing may route out:\n%s", none)
	}

	// No approved devices → nothing forwardable.
	empty := renderReachability(nets, map[int64]netPolicy{}, "eth0", testPrivateRanges, routeOrigin{}, "")
	if fwd := empty[strings.Index(empty, "chain forward"):strings.Index(empty, "chain input")]; strings.Count(fwd, " accept\n") != 1 { // only the ct accept
		t.Fatalf("with no devices, only the established accept may exist in forward:\n%s", empty)
	}

	// Invalid values are never emitted.
	bad := map[int64]netPolicy{1: {Devices: []devicePolicy{
		{IP: "not-an-ip", MAC: "02:00:00:00:00:01", Allowed: []vpnGrant{{IP: "1.2.3.4; flush ruleset", Both: true}}, Internet: true},
		{IP: "10.20.20.77", MAC: "02:00:00:00:00:77; flush ruleset", Internet: true},
		{IP: "10.20.20.78", MAC: "02:00:00:00:00:78", VPNIP: "10.8.128.9; flush ruleset", Allowed: []vpnGrant{{IP: "10.8.0.2", Both: true}}},
	}, Blocked: []string{"zz:zz"}}}
	if out := renderReachability(nets, bad, "eth0", testPrivateRanges, routeOrigin{}, ""); strings.Contains(out, "flush") || strings.Contains(out, "zz:zz") || strings.Contains(out, "not-an-ip") || strings.Contains(out, "10.20.20.77") {
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
			Allowed: []vpnGrant{{IP: "10.8.0.2", Both: true}, {IP: "10.8.0.3"}}, Internet: true, Out: portsOf("all,web"), Routes: []int{80, 443}},
			{IP: "10.20.20.56", MAC: "02:00:00:00:00:56", VPNIP: "10.8.128.6", Routes: []int{8080}},
			{IP: "10.20.20.57", MAC: "02:00:00:00:00:57", Internet: true, Egress: "203.0.113.10", Out: portsOf("web,time,smtp,udp:5000,ping"),
				In: inboundRules([]inboundEntry{{Entry: "ssh", Sources: []string{"198.51.100.0/24", "203.0.113.7/32"}}, {Entry: "web", Sources: []string{"any"}}, {Entry: "udp:5000", Sources: []string{"any"}}})}},
			Blocked: []string{"02:00:00:00:00:09"}, Dedicated: []string{"203.0.113.10", "203.0.113.11"}},
		2: {Devices: []devicePolicy{{IP: "192.168.50.20", MAC: "02:00:00:00:00:20", PrivateRoutes: true}}},
	}
	// A device allowed outside DNS: its lookups to other servers skip the AdGuard redirect.
	pol[1].Devices[2].Out = portsOf("web,time,smtp,udp:5000,ping,dns")
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("HEADSCALE_IP_RANGE", "100.64.0.0/10")
	ranges := privateReachRanges() // the real list, so nft checks the set as it ships
	// The leak guard covers every non-public block, the cloud metadata address included.
	for _, want := range []string{"169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "240.0.0.0/4", "10.8.0.0/16"} {
		if !slices.Contains(ranges, want) {
			t.Fatalf("leak guard misses %s: %v", want, ranges)
		}
	}
	script := renderReachability(nets, pol, "eth0", ranges, routeOrigin{Iface: "br-0123456789ab", IP: "172.18.0.2"}, "10.8.0.1")

	// DNS to each enabled network's gateway is handed to AdGuard; a disabled network gets nothing.
	for _, want := range []string{
		`iifname "ens19" ip daddr 10.20.20.1 meta l4proto { tcp, udp } th dport 53 dnat ip to 10.8.0.1`,
		`iifname "ens20" ip daddr 192.168.50.1 meta l4proto { tcp, udp } th dport 53 dnat ip to 10.8.0.1`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing DNS hand-over %q:\n%s", want, script)
		}
	}
	// A device let in to private routes reaches Traefik's HTTPS, only through the server's VPN address.
	private := `iifname "ens20" ether saddr 02:00:00:00:00:20 ip saddr 192.168.50.20 ip daddr 172.18.0.2 oifname "br-0123456789ab" tcp dport 443 ct status dnat ct original ip daddr 10.8.0.1 accept`
	if at, drop := strings.Index(script, private), strings.Index(script, "ip saddr 192.168.50.0/24 drop"); at < 0 || at > drop {
		t.Fatalf("missing private-route rule above the network's closing drop %q:\n%s", private, script)
	}
	if strings.Count(script, "ct original ip daddr 10.8.0.1") != 1 {
		t.Fatalf("only the device let in to private routes may reach Traefik:\n%s", script)
	}

	// Anti-spoofing: each enabled network drops sources outside its range, routed and to the box
	// (where only a new device's 0.0.0.0 is let through, for DHCP).
	for _, want := range []string{
		`iifname "ens19" ip saddr != 10.20.20.0/24 drop`,
		`iifname "ens19" ip saddr != 10.20.20.0/24 ip saddr != 0.0.0.0 drop`,
		`iifname "ens20" ip saddr != 192.168.50.0/24 drop`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing anti-spoofing rule %q:\n%s", want, script)
		}
	}
	if fwdAt, spoofAt := strings.Index(script, "ct state established,related accept"), strings.Index(script, `iifname "ens19" ip saddr != 10.20.20.0/24 drop`); spoofAt < 0 || spoofAt > fwdAt {
		t.Fatalf("anti-spoofing must sit above the established/related accept:\n%s", script)
	}
	if strings.Contains(script, "172.16.0.1 meta l4proto") {
		t.Fatalf("a disabled network got a DNS hand-over:\n%s", script)
	}

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

// Without a valid AdGuard address (or gateway) no DNS hand-over is written: nothing points anywhere.
func TestDNSHandOverNeedsValidAddresses(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true}}
	pol := map[int64]netPolicy{1: {}}
	for _, dns := range []string{"", "not-an-ip", "10.8.0.0/24", "fd00::1"} {
		if out := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{}, dns); strings.Contains(out, "dport 53 dnat") {
			t.Fatalf("dns %q wrote a hand-over:\n%s", dns, out)
		}
	}
	bad := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "", Enabled: true}}
	if out := renderReachability(bad, pol, "eth0", testPrivateRanges, routeOrigin{}, "10.8.0.1"); strings.Contains(out, "dport 53 dnat") {
		t.Fatalf("no gateway, but a hand-over:\n%s", out)
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

// Routed IPv6 to or from a segment is dropped (every other rule matches IPv4 only), above the
// established accept so open IPv6 connections are cut too; a disabled network gets nothing.
func TestReachabilityDropsIPv6(t *testing.T) {
	nets := []Network{
		{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true},
		{ID: 2, Iface: "ens21", CIDR: "10.30.30.0/24", GatewayIP: "10.30.30.1", Enabled: false},
	}
	got := renderReachability(nets, map[int64]netPolicy{}, "eth0", testPrivateRanges, routeOrigin{}, "")
	est := strings.Index(got, "ct state established,related accept")
	for _, want := range []string{`iifname "ens19" meta nfproto ipv6 drop`, `oifname "ens19" meta nfproto ipv6 drop`} {
		i := strings.Index(got, want)
		if i < 0 || i > est {
			t.Fatalf("missing %q above the established accept:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"ens21" meta nfproto ipv6`) {
		t.Fatalf("a disabled network must get no rules:\n%s", got)
	}
}

// A network can't be put on loopback, a VPN, Docker or virtual plumbing, or a NIC that doesn't
// exist, even by a request that skips the UI's list (every case errors on any host: an
// undetectable WAN is refused too).
func TestRequireLANInterfaceRefuses(t *testing.T) {
	for _, iface := range []string{"lo", "wg0", "tailscale0", "docker0", "br-0123456789ab", "veth1234", "tun0", "nosuchnic0"} {
		if err := requireLANInterface(iface); err == nil {
			t.Errorf("%s was accepted for a LAN", iface)
		}
	}
	for name, ok := range map[string]bool{"ens19": true, "eth1": true, "eth0": false, "lo": false, "wg0": false, "docker0": false, "virbr0": false} {
		if got := candidateInterface(name, "eth0"); got != ok {
			t.Errorf("candidateInterface(%q, wan eth0) = %v, want %v", name, got, ok)
		}
	}
}

// A network that reaches dnsmasq by another path than the form (a restored backup) is checked
// again: a value that doesn't hold up — a domain smuggling a second directive, a gateway outside
// the subnet, an unchecked form — keeps the network out of dnsmasq.
func TestCheckDnsmasqNetwork(t *testing.T) {
	good := Network{Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", PoolStart: "10.20.20.50",
		PoolEnd: "10.20.20.200", LeaseSecs: 3600, Mode: "approve", Domain: "lan"}
	if err := checkDnsmasqNetwork(&good); err != nil {
		t.Fatalf("a valid network was refused: %v", err)
	}
	for name, mut := range map[string]func(n *Network){
		"domain with a directive": func(n *Network) { n.Domain = "lan\ndhcp-script=/bin/sh" },
		"gateway outside":         func(n *Network) { n.GatewayIP = "10.99.0.1" },
		"pool start not an IP":    func(n *Network) { n.PoolStart = "10.20.20.50\nconf-file=/x" },
		"unmasked subnet":         func(n *Network) { n.CIDR = "10.20.20.7/24" },
		"bad interface":           func(n *Network) { n.Iface = "ens19\ninterface=eth0" },
		"public subnet": func(n *Network) {
			n.CIDR, n.GatewayIP, n.PoolStart, n.PoolEnd = "203.0.113.0/24", "203.0.113.1", "203.0.113.50", "203.0.113.60"
		},
	} {
		n := good
		mut(&n)
		if err := checkDnsmasqNetwork(&n); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Reservations and blocked MACs that don't hold up are never written.
	out := renderDnsmasqConf(&good, []Client{
		{MAC: "02:00:00:00:00:01", IP: "10.20.20.60", Name: "ok"},
		{MAC: "02:00:00:00:00:02\ndhcp-script=/x", IP: "10.20.20.61"},
		{MAC: "02:00:00:00:00:03", IP: "10.99.0.5"},
	}, []string{"02:00:00:00:00:09", "02:00:00:00:00:0a\nconf-dir=/x"})
	if !strings.Contains(out, "dhcp-host=02:00:00:00:00:01,10.20.20.60,ok") || strings.Contains(out, "dhcp-script") ||
		strings.Contains(out, "conf-dir") || strings.Contains(out, "10.99.0.5") {
		t.Fatalf("only valid hosts may be written:\n%s", out)
	}
}

// A Traefik address a container could forge closes the routes to LAN devices (Traefik as a source)
// but not the way LAN devices reach Traefik for private routes; an unknown address closes both.
func TestTraefikOriginTrust(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true}}
	pol := map[int64]netPolicy{1: {Devices: []devicePolicy{
		{IP: "10.20.20.55", MAC: "02:00:00:00:00:55", VPNIP: "10.8.128.5", Allowed: []vpnGrant{{IP: "10.8.0.2"}}, Routes: []int{8080}},
		{IP: "10.20.20.56", MAC: "02:00:00:00:00:56", PrivateRoutes: true},
	}}}
	const route, private = "tcp dport 8080 dnat ip to 10.20.20.55", "ct original ip daddr 10.8.0.1 accept"
	for _, c := range []struct {
		name                  string
		origin                routeOrigin
		wantRoute, wantPrivat bool
	}{
		{"trusted", routeOrigin{Iface: "br-0123456789ab", IP: "172.18.0.2"}, true, true},
		{"forgeable", routeOrigin{Iface: "br-0123456789ab", IP: "172.18.0.2", Forgeable: true}, false, true},
		{"unknown", routeOrigin{}, false, false},
	} {
		script := renderReachability(nets, pol, "eth0", nil, c.origin, "10.8.0.1")
		if got := strings.Contains(script, route); got != c.wantRoute {
			t.Errorf("%s: route to the LAN device emitted = %v, want %v", c.name, got, c.wantRoute)
		}
		if got := strings.Contains(script, private); got != c.wantPrivat {
			t.Errorf("%s: private-route rule emitted = %v, want %v", c.name, got, c.wantPrivat)
		}
		paths := accessOf(nets, pol, "eth0", c.origin)
		if paths["02:00:00:00:00:55"].Paths["route 8080"] != c.wantRoute || paths["02:00:00:00:00:56"].Paths["private routes"] != c.wantPrivat {
			t.Errorf("%s: access paths disagree with the rules: %+v", c.name, paths)
		}
	}
}
