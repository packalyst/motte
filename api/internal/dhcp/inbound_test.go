package dhcp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/router"
)

// A list is validated and kept in one order; anything not understood is refused, never skipped.
func TestNormalizeInbound(t *testing.T) {
	got, err := normalizeInbound([]inboundEntry{
		{Entry: "tcp:2222", Sources: []string{"198.51.100.7", "203.0.113.0/24", "198.51.100.7"}},
		{Entry: " SSH ", Sources: []string{"any"}},
		{Entry: "web", Sources: []string{"203.0.113.5/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[{web [203.0.113.0/24]} {ssh [any]} {tcp:2222 [198.51.100.7/32 203.0.113.0/24]}]" {
		t.Fatalf("got %v", got)
	}
	many := make([]inboundEntry, maxInboundEntries+1)
	for i := range many {
		many[i] = inboundEntry{Entry: fmt.Sprintf("tcp:%d", 1000+i), Sources: []string{"any"}}
	}
	manySrc := make([]string, maxInboundSources+1)
	for i := range manySrc {
		manySrc[i] = fmt.Sprintf("203.0.113.%d", i+1)
	}
	for name, bad := range map[string][]inboundEntry{
		"all other ports":   {{Entry: "all", Sources: []string{"any"}}},
		"port 25 by hand":   {{Entry: "tcp:25", Sources: []string{"any"}}},
		"unknown":           {{Entry: "ftp", Sources: []string{"any"}}},
		"injection":         {{Entry: "tcp:22; flush ruleset", Sources: []string{"any"}}},
		"twice":             {{Entry: "ssh", Sources: []string{"any"}}, {Entry: "SSH", Sources: []string{"any"}}},
		"no sources":        {{Entry: "ssh"}},
		"anyone and more":   {{Entry: "ssh", Sources: []string{"any", "203.0.113.1"}}},
		"private source":    {{Entry: "ssh", Sources: []string{"10.0.0.0/8"}}},
		"everyone by range": {{Entry: "ssh", Sources: []string{"0.0.0.0/0"}}},
		"metadata":          {{Entry: "ssh", Sources: []string{"169.254.169.254"}}},
		"ipv6":              {{Entry: "ssh", Sources: []string{"2001:db8::1"}}},
		"bad source":        {{Entry: "ssh", Sources: []string{"203.0.113.1; drop"}}},
		"too many sources":  {{Entry: "ssh", Sources: manySrc}},
		"too many entries":  many,
	} {
		if _, err := normalizeInbound(bad); err == nil {
			t.Errorf("%s: passed", name)
		}
	}
}

// Opening something new, or to more sources, widens; narrowing doesn't.
func TestWidensInbound(t *testing.T) {
	e := func(entry string, src ...string) inboundEntry { return inboundEntry{Entry: entry, Sources: src} }
	for _, c := range []struct {
		old, new []inboundEntry
		want     bool
	}{
		{nil, []inboundEntry{e("ssh", "203.0.113.1/32")}, true},
		{[]inboundEntry{e("ssh", "203.0.113.0/24")}, []inboundEntry{e("ssh", "203.0.113.1/32")}, false},
		{[]inboundEntry{e("ssh", "203.0.113.1/32")}, []inboundEntry{e("ssh", "203.0.113.0/24")}, true},
		{[]inboundEntry{e("ssh", "203.0.113.1/32")}, []inboundEntry{e("ssh", "any")}, true},
		{[]inboundEntry{e("ssh", "any")}, []inboundEntry{e("ssh", "203.0.113.1/32")}, false},
		{[]inboundEntry{e("ssh", "any"), e("web", "any")}, []inboundEntry{e("ssh", "any")}, false},
		{[]inboundEntry{e("ssh", "any")}, []inboundEntry{e("ssh", "any"), e("web", "any")}, true},
	} {
		if got := widensInbound(c.old, c.new); got != c.want {
			t.Errorf("%v → %v: %v, want %v", c.old, c.new, got, c.want)
		}
	}
}

// A stored value never opens more than it says: garbage opens nothing, and sources that don't read
// back mean nobody, never anyone.
func TestInboundRulesFromStore(t *testing.T) {
	got := inboundRules([]inboundEntry{
		{Entry: "all", Sources: []string{"any"}},
		{Entry: "nonsense", Sources: []string{"any"}},
		{Entry: "ssh", Sources: []string{"not-an-ip"}},
		{Entry: "ssh", Sources: []string{"10.0.0.0/8"}},
		{Entry: "web", Sources: []string{"any"}},
		{Entry: "tcp:2222", Sources: []string{"203.0.113.0/24"}},
	})
	if fmt.Sprint(got) != "[{[80 443] [443] []} {[2222] [] [203.0.113.0/24]}]" {
		t.Fatalf("got %v", got)
	}
}

// A device with ways in gets, for each, the exception above its dedicated address's drop, the
// hand-over to it and the forward accept for exactly that; nothing for a device without its own
// address or without internet.
func TestReachabilityInbound(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true}}
	in := inboundRules([]inboundEntry{{Entry: "ssh", Sources: []string{"198.51.100.7/32"}}, {Entry: "web", Sources: []string{"any"}}})
	pol := map[int64]netPolicy{1: {Devices: []devicePolicy{
		{IP: "10.20.20.55", MAC: "02:00:00:00:00:55", Internet: true, Egress: "203.0.113.10", Out: portsOf("web"), In: in},
		{IP: "10.20.20.56", MAC: "02:00:00:00:00:56", Internet: true, Out: portsOf("web"), In: in},       // main address
		{IP: "10.20.20.57", MAC: "02:00:00:00:00:57", Internet: false, Egress: "203.0.113.11", In: in},   // internet off
		{IP: "10.20.20.58", MAC: "02:00:00:00:00:58", Internet: true, Egress: "203.0.113.11; x", In: in}, // invalid address
	}, Dedicated: []string{"203.0.113.10", "203.0.113.11"}}}
	got := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{})
	for _, want := range []string{
		`iifname "eth0" ip daddr 203.0.113.10 ip saddr { 198.51.100.7/32 } tcp dport 22 accept`,
		`iifname "eth0" ip daddr 203.0.113.10 tcp dport { 80, 443 } accept`,
		`iifname "eth0" ip daddr 203.0.113.10 udp dport 443 accept`,
		`iifname "eth0" ip daddr 203.0.113.10 ip saddr { 198.51.100.7/32 } tcp dport 22 dnat ip to 10.20.20.55`,
		`iifname "eth0" oifname "ens19" ip daddr 10.20.20.55 ip saddr { 198.51.100.7/32 } tcp dport 22 ct status dnat ct original ip daddr 203.0.113.10 accept`,
		`type nat hook prerouting priority -110; policy accept;`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	for _, ip := range []string{"10.20.20.56", "10.20.20.57", "10.20.20.58"} {
		if strings.Contains(got, "dnat ip to "+ip) || strings.Contains(got, "ip daddr "+ip+" ") {
			t.Fatalf("%s must take nothing in:\n%s", ip, got)
		}
	}
	// The exceptions sit above the dedicated address's drop, in the same chain.
	chain := got[strings.Index(got, "chain dedicated_in"):strings.Index(got, "chain inbound_dnat")]
	if strings.Index(chain, "tcp dport 22 accept") > strings.Index(chain, "@dedicated_addrs ct state") {
		t.Fatalf("ways in must come before the drop:\n%s", chain)
	}
	// The forward accept comes before the segment's closing drop.
	if strings.Index(got, "ct original ip daddr 203.0.113.10 accept") > strings.Index(got, "ip daddr 10.20.20.0/24 drop") {
		t.Fatalf("forward accept must come before the closing drop:\n%s", got)
	}
	if !pol[1].hasInbound() || (netPolicy{Devices: pol[1].Devices[1:]}).hasInbound() {
		t.Fatal("hasInbound: only a device on its own address with internet takes connections in")
	}

	// Narrowing a source cuts the connections in, through the dedicated address.
	before := accessOf(nets, pol, "eth0", routeOrigin{})
	narrowed := inboundRules([]inboundEntry{{Entry: "web", Sources: []string{"any"}}})
	pol[1].Devices[0].In = narrowed
	lost := strings.Join(lostAccess(before, accessOf(nets, pol, "eth0", routeOrigin{})), ",")
	if !strings.Contains(lost, "203.0.113.10") || !strings.Contains(lost, "10.20.20.55") {
		t.Fatalf("taking a way in away must cut through the dedicated address: %v", lost)
	}
}

// End to end through the handler: incoming needs the device's own dedicated address and a step-up
// to open or widen; narrowing doesn't; moving the device deletes its list; switched off, nothing
// comes in, and switched on again (step-up) it all comes back.
func TestInboundSave(t *testing.T) {
	t.Setenv("PATH", "") // the handler re-applies the network: never run iptables/ip on the test host
	stubWAN(t, false)
	s := egressTestService(t)
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
	s.db.QueryRow(`SELECT id FROM dhcp_clients`).Scan(&dev)
	stepUpOK := true
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
	list := func() string { l, _ := s.listInbound(dev); return inboundLabel(l) }
	policyIn := func() int {
		p, err := s.networkPolicy(n)
		if err != nil || len(p.Devices) != 1 {
			t.Fatalf("policy: %v %v", p, err)
		}
		return len(p.Devices[0].In)
	}
	ssh := `"inbound":[{"entry":"ssh","sources":["198.51.100.7"]}]`

	if code := set(`{"enabled":true,` + ssh + `}`); code != http.StatusConflict || list() != "nothing" {
		t.Fatalf("incoming on the network's address: %d %q", code, list())
	}
	if code := set(`{"enabled":true,"egress_ip":"main",` + ssh + `}`); code != http.StatusBadRequest {
		t.Fatalf("incoming with an address move in one save: %d", code)
	}
	if code := set(`{"enabled":true,"egress_ip":"203.0.113.11"}`); code != http.StatusOK {
		t.Fatalf("own address: %d", code)
	}
	stepUpOK = false
	if code := set(`{"enabled":true,` + ssh + `}`); code != http.StatusPreconditionRequired || list() != "nothing" {
		t.Fatalf("opening without step-up: %d %q", code, list())
	}
	stepUpOK = true
	if code := set(`{"enabled":true,"inbound":[{"entry":"ssh","sources":["198.51.100.0/24"]}]}`); code != http.StatusOK || policyIn() != 1 {
		t.Fatalf("opening with step-up: %d", code)
	}
	stepUpOK = false
	if code := set(`{"enabled":true,` + ssh + `}`); code != http.StatusOK || list() != "SSH from 198.51.100.7/32" {
		t.Fatalf("narrowing needs no step-up: %d %q", code, list())
	}
	if code := set(`{"enabled":true,"inbound":[{"entry":"ssh","sources":["any"]}]}`); code != http.StatusPreconditionRequired {
		t.Fatalf("widening to anyone without step-up: %d", code)
	}
	// Off: kept, but nothing comes in. On again: step-up, and it is back.
	if code := set(`{"enabled":false}`); code != http.StatusOK || list() == "nothing" || policyIn() != 0 {
		t.Fatalf("off: %d %q in=%d", code, list(), policyIn())
	}
	if code := set(`{"enabled":true}`); code != http.StatusPreconditionRequired || policyIn() != 0 {
		t.Fatalf("on again without step-up: %d", code)
	}
	stepUpOK = true
	if code := set(`{"enabled":true}`); code != http.StatusOK || policyIn() != 1 {
		t.Fatalf("on again: %d in=%d", code, policyIn())
	}
	// Moving the device deletes its list with the address.
	if code := set(`{"enabled":true,"egress_ip":"main"}`); code != http.StatusOK || list() != "nothing" {
		t.Fatalf("moving: %d %q", code, list())
	}
	// Forgetting the device takes its list too.
	if code := set(`{"enabled":true,"egress_ip":"203.0.113.11"}`); code != http.StatusOK {
		t.Fatal(code)
	}
	if code := set(`{"enabled":true,` + ssh + `}`); code != http.StatusOK {
		t.Fatal(code)
	}
	if _, err := s.deleteClient(dev); err != nil {
		t.Fatal(err)
	}
	var left int
	s.db.QueryRow(`SELECT COUNT(*) FROM dhcp_inbound`).Scan(&left)
	if left != 0 {
		t.Fatalf("a forgotten device's incoming rules must go with it: %d left", left)
	}
}

// The Docker opening for incoming lets through only what inbound_dnat handed over, WAN to that
// segment: never a plain new connection from the WAN.
func TestSegmentInboundForward(t *testing.T) {
	_, back, in := segmentWANRules("ens19", "eth0")
	if strings.Join(in, " ") != "-i eth0 -o ens19 -m conntrack --ctstate DNAT" {
		t.Fatalf("in: %v", in)
	}
	if strings.Join(back, " ") != "-i eth0 -o ens19 -m conntrack --ctstate ESTABLISHED,RELATED" {
		t.Fatalf("back: %v", back)
	}
}
