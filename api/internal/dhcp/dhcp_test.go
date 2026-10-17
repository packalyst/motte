package dhcp

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

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
	for _, want := range []string{
		"port=0",
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
