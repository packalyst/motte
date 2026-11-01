package dhcp

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/router"
)

// The server's addresses for these tests: it sends from 198.51.100.1, the panel is 198.51.100.2,
// and 203.0.113.10/.11 are extra public addresses (documentation ranges only).
func stubWAN(t *testing.T, fail bool) {
	t.Helper()
	t.Setenv("SERVER_IP", "198.51.100.2")
	prev := wanAddresses
	wanAddresses = func() (string, string, []string, error) {
		if fail {
			return "", "", nil, errors.New("no route")
		}
		return "eth0", "198.51.100.1", []string{"198.51.100.1", "198.51.100.2", "203.0.113.10", "203.0.113.11", "10.0.0.5"}, nil
	}
	t.Cleanup(func() { wanAddresses = prev })
}

// Only extra public addresses are offered: never the address the server sends from, the panel's
// address, or a private one.
func TestEgressAddrs(t *testing.T) {
	stubWAN(t, false)
	e, err := loadEgressAddrs()
	if err != nil {
		t.Fatal(err)
	}
	if e.Main != "198.51.100.1" || strings.Join(e.Extras, ",") != "203.0.113.10,203.0.113.11" {
		t.Fatalf("got %+v", e)
	}
	for _, c := range []struct {
		v         string
		allowMain bool
		want      string
		ok        bool
	}{
		{"", false, "", true},
		{" 203.0.113.10 ", false, "203.0.113.10", true},
		{"main", true, "main", true},
		{"main", false, "", false},         // a network has no "main" choice: "" is the main address
		{"198.51.100.1", false, "", false}, // the server's own address
		{"198.51.100.2", true, "", false},  // the panel's address
		{"10.0.0.5", true, "", false},      // private
		{"203.0.113.99", true, "", false},  // not on the server
		{"203.0.113.10; drop", true, "", false},
	} {
		got, err := checkEgress(c.v, c.allowMain)
		if (err == nil) != c.ok || (c.ok && got != c.want) {
			t.Errorf("checkEgress(%q, %v) = %q, %v", c.v, c.allowMain, got, err)
		}
	}
	stubWAN(t, true)
	if _, err := checkEgress("203.0.113.10", true); err == nil {
		t.Fatal("an extra address must be refused when the server can't be read")
	}
}

// A device leaves from its own address, else its network's; "main" overrides the network; an
// address that left the server takes the device's internet away instead of falling back.
func TestEgressResolve(t *testing.T) {
	stubWAN(t, false)
	n := &Network{Egress: "203.0.113.10"}
	var r egressResolver
	for _, c := range []struct {
		dev, want string
		ok        bool
	}{
		{"", "203.0.113.10", true},
		{"main", "", true},
		{"203.0.113.11", "203.0.113.11", true},
		{"203.0.113.99", "", false},
	} {
		got, ok := r.resolve(n, &Client{MAC: "02:00:00:00:00:01", Egress: c.dev})
		if got != c.want || ok != c.ok {
			t.Errorf("device %q: got %q %v", c.dev, got, ok)
		}
	}
	if got, ok := r.resolve(&Network{}, &Client{}); got != "" || !ok {
		t.Fatal("no address anywhere is the main address")
	}
	stubWAN(t, true)
	var down egressResolver
	if _, ok := down.resolve(n, &Client{}); ok {
		t.Fatal("an extra address must not be used when the server can't be read")
	}
}

// Each device leaves from its own address; an extra address accepts no connection in; a device
// whose address is unusable gets neither the way out nor NAT.
func TestReachabilityEgress(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true}}
	pol := map[int64]netPolicy{1: {Devices: []devicePolicy{
		{IP: "10.20.20.55", MAC: "02:00:00:00:00:55", Internet: true, Out: outPorts{All: true}},
		{IP: "10.20.20.56", MAC: "02:00:00:00:00:56", Internet: true, Egress: "203.0.113.10", Out: outPorts{All: true}},
		{IP: "10.20.20.57", MAC: "02:00:00:00:00:57", Internet: true, Egress: "203.0.113.10; flush ruleset"},
	}, Dedicated: []string{"203.0.113.10", "203.0.113.11", "bad"}}}
	got := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{})
	for _, want := range []string{
		`ip saddr 10.20.20.55 oifname "eth0" masquerade`,
		`ip saddr 10.20.20.56 oifname "eth0" snat ip to 203.0.113.10`,
		`iifname "ens19" ether saddr 02:00:00:00:00:56 ip saddr 10.20.20.56 oifname "eth0" accept`,
		`elements = { 203.0.113.10, 203.0.113.11 }`,
		`type filter hook prerouting priority -150; policy accept;`,
		`ip daddr @dedicated_addrs ct state != { established, related } drop`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "10.20.20.57") && strings.Contains(got, `saddr 10.20.20.57 oifname`) || strings.Contains(got, "flush") || strings.Contains(got, "bad") {
		t.Fatalf("an invalid address must keep the device in, and never reach the ruleset:\n%s", got)
	}
	// The address in use for a device is part of its access: moving it cuts its open connections.
	a := accessOf(nets, pol, "eth0", routeOrigin{})
	moved := map[int64]netPolicy{1: {Devices: []devicePolicy{{IP: "10.20.20.56", MAC: "02:00:00:00:00:56", Internet: true, Out: outPorts{All: true}}}}}
	if lost := lostAccess(a, accessOf(nets, moved, "eth0", routeOrigin{})); !strings.Contains(strings.Join(lost, ","), "10.20.20.56") {
		t.Fatalf("a device moved to another address must have its connections cut: %v", lost)
	}
}

// The panel's address and the one the server sends from are never closed, even when a stored
// choice names them (the host's addresses changed after it was picked).
func TestDedicatedKeepsServerOpen(t *testing.T) {
	stubWAN(t, false)
	pol := map[int64]netPolicy{1: {Dedicated: []string{"198.51.100.1", "198.51.100.2", "203.0.113.10"}}, 2: {}}
	keepServerAddressesOpen(pol)
	if got := strings.Join(pol[1].Dedicated, ","); got != "203.0.113.10" {
		t.Fatalf("got %q", got)
	}
}

// The stored choices reach the policy: the network default, a device's own address, the explicit
// main address; every named extra address is closed, even for a device with internet off.
func TestNetworkPolicyEgress(t *testing.T) {
	stubWAN(t, false)
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DELETE FROM dhcp_clients`, `DELETE FROM dhcp_networks`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{db: db}
	n := &Network{Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", PoolStart: "10.20.20.50",
		PoolEnd: "10.20.20.200", LeaseSecs: 3600, Mode: "auto", NATEnabled: true, Enabled: true, Egress: "203.0.113.10"}
	if n.ID, err = s.createNetwork(n); err != nil {
		t.Fatal(err)
	}
	devs := []struct{ mac, ip, egress string }{
		{"02:00:00:00:00:01", "10.20.20.51", ""},
		{"02:00:00:00:00:02", "10.20.20.52", "main"},
		{"02:00:00:00:00:03", "10.20.20.53", "203.0.113.11"},
		{"02:00:00:00:00:04", "10.20.20.54", "203.0.113.99"}, // gone from the server
	}
	for _, d := range devs {
		if err := s.upsertClient(n.ID, d.mac, d.ip, "", true); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE dhcp_clients SET egress_ip = ? WHERE mac = ?`, d.egress, d.mac); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.networkPolicy(n)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		egress   string
		internet bool
	}{
		"10.20.20.51": {"203.0.113.10", true},
		"10.20.20.52": {"", true},
		"10.20.20.53": {"203.0.113.11", true},
		"10.20.20.54": {"", false},
	}
	for _, d := range p.Devices {
		if w := want[d.IP]; d.Egress != w.egress || d.Internet != w.internet {
			t.Errorf("%s: egress %q internet %v, want %+v", d.IP, d.Egress, d.Internet, w)
		}
	}
	if got := strings.Join(p.Dedicated, ","); got != "203.0.113.10,203.0.113.11,203.0.113.99" {
		t.Fatalf("dedicated: %q", got)
	}
}

// Turning a device's internet on, or moving it to another address while on, needs the step-up;
// turning it off doesn't. An address that isn't an extra one on the server is refused.
func TestInternetSwitchStepUp(t *testing.T) {
	t.Setenv("PATH", "") // the handler re-applies the network: never run iptables/ip on the test host
	stubWAN(t, false)
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, _ := database.GetDB()
	for _, q := range []string{`DELETE FROM dhcp_clients`, `DELETE FROM dhcp_networks`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{db: db}
	n := &Network{Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", PoolStart: "10.20.20.50",
		PoolEnd: "10.20.20.200", LeaseSecs: 3600, Mode: "auto", Enabled: true}
	var err error
	if n.ID, err = s.createNetwork(n); err != nil {
		t.Fatal(err)
	}
	if err := s.upsertClient(n.ID, "02:00:00:00:00:01", "10.20.20.51", "", true); err != nil {
		t.Fatal(err)
	}
	var dev int64
	db.QueryRow(`SELECT id FROM dhcp_clients`).Scan(&dev)

	stepUpOK := false
	router.SetStepUpFunc(func(w http.ResponseWriter, _ *http.Request) bool {
		if !stepUpOK {
			w.WriteHeader(http.StatusPreconditionRequired)
		}
		return stepUpOK
	})
	t.Cleanup(func() { router.SetStepUpFunc(nil) })
	set := func(body string) int {
		rr := httptest.NewRecorder()
		s.handleSetInternet(rr, httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/dhcp/clients/%d/internet", dev), strings.NewReader(body)))
		return rr.Code
	}
	state := func() (on bool, egress string) {
		c, _ := s.getClient(dev)
		return c.Internet, c.Egress
	}

	if code := set(`{"enabled":true}`); code != http.StatusPreconditionRequired {
		t.Fatalf("on without step-up: %d", code)
	}
	if on, _ := state(); on {
		t.Fatal("no step-up, no internet")
	}
	stepUpOK = true
	if code := set(`{"enabled":true,"egress_ip":"203.0.113.10"}`); code != http.StatusOK {
		t.Fatalf("on with step-up: %d", code)
	}
	if on, eg := state(); !on || eg != "203.0.113.10" {
		t.Fatalf("got %v %q", on, eg)
	}
	stepUpOK = false
	if code := set(`{"enabled":true,"egress_ip":"main"}`); code != http.StatusPreconditionRequired {
		t.Fatalf("moving to another address without step-up: %d", code)
	}
	if _, eg := state(); eg != "203.0.113.10" {
		t.Fatalf("no step-up, address unchanged: %q", eg)
	}
	for _, bad := range []string{"198.51.100.2", "203.0.113.99", "10.0.0.5"} {
		if code := set(`{"enabled":true,"egress_ip":"` + bad + `"}`); code != http.StatusBadRequest {
			t.Fatalf("%s: %d, want 400", bad, code)
		}
	}
	// Services: taking one away needs no step-up, adding one does; unknown ones are refused.
	svc := func() string { c, _ := s.getClient(dev); return c.Services }
	if code := set(`{"enabled":true,"services":"web"}`); code != http.StatusOK || svc() != "web" {
		t.Fatalf("narrowing to web: %d %q", code, svc())
	}
	if code := set(`{"enabled":true,"services":"web,ssh"}`); code != http.StatusPreconditionRequired || svc() != "web" {
		t.Fatalf("adding ssh without step-up: %d %q", code, svc())
	}
	for _, bad := range []string{"tcp:25", "ftp"} {
		if code := set(`{"enabled":true,"services":"` + bad + `"}`); code != http.StatusBadRequest {
			t.Fatalf("services %q: %d, want 400", bad, code)
		}
	}
	stepUpOK = true
	if code := set(`{"enabled":true,"services":"all"}`); code != http.StatusOK || svc() != "all" {
		t.Fatalf("everything with step-up: %d %q", code, svc())
	}
	stepUpOK = false

	if code := set(`{"enabled":false}`); code != http.StatusOK {
		t.Fatalf("off needs no step-up: %d", code)
	}
	if on, eg := state(); on || eg != "203.0.113.10" {
		t.Fatalf("off keeps the chosen address for next time: %v %q", on, eg)
	}
}
