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
		if want := "/dhcp-conf/wgpanel-" + iface + ".conf"; p != want {
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
	got := renderDnsmasqConf(n, res)
	// port=0 is a GLOBAL that lives ONLY in the base conf — repeating it here makes dnsmasq
	// crash-loop with "illegal repeated keyword". (Regression guard, 2026-10-18.)
	if strings.Contains(got, "port=0") {
		t.Fatalf("per-network conf must not repeat the base global port=0:\n%s", got)
	}
	for _, want := range []string{
		"interface=ens19",
		"dhcp-range=10.20.20.50,10.20.20.200,255.255.255.0,43200s",
		"dhcp-option=3,10.20.20.1",
		"dhcp-host=aa:bb:cc:dd:ee:ff,set:known,10.20.20.50,cam-1", // name sanitized, approve tag
		"dhcp-ignore=tag:!known",                                  // approve mode isolates unknowns
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("dnsmasq conf missing %q:\n%s", want, got)
		}
	}

	// Auto mode must NOT ignore unknowns and must NOT tag reservations.
	n.Mode = "auto"
	got = renderDnsmasqConf(n, res)
	if strings.Contains(got, "dhcp-ignore") || strings.Contains(got, "set:known") {
		t.Fatalf("auto mode should not gate unknown clients:\n%s", got)
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
	allowed := map[int64][]string{1: {"10.8.0.2", "10.8.0.3"}}
	script := renderReachability(nets, allowed, "eth0")

	// Disabled network must not appear; NAT-off network must not get a masquerade.
	if strings.Contains(script, "172.16.0.0") {
		t.Fatalf("disabled network leaked into ruleset:\n%s", script)
	}
	if strings.Contains(script, "192.168.50.0/24 oifname") {
		t.Fatalf("NAT-off network got an internet-out accept:\n%s", script)
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
