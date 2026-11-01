package dhcp

import (
	"fmt"
	"strings"
	"testing"
)

// Lists are validated and kept in one order; port 25 only through Direct mail; anything unknown
// is refused.
func TestNormalizeServices(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{" time , WEB,web ", "web,time"},
		{"udp:5000,tcp:8883,ssh,tcp:443", "ssh,tcp:443,tcp:8883,udp:5000"},
		{"smtp,all", "all,smtp"},
	} {
		if got, err := normalizeServices(c.in); err != nil || got != c.want {
			t.Errorf("normalizeServices(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"tcp:25", "ftp", "tcp:0", "tcp:65536", "tcp:080", "icmp:1", "tcp:22; drop", "tcp:-1"} {
		if _, err := normalizeServices(bad); err == nil {
			t.Errorf("normalizeServices(%q) passed", bad)
		}
	}
	var many []string
	for i := 1; i <= maxServiceEntries+1; i++ {
		many = append(many, fmt.Sprintf("udp:%d", 1000+i))
	}
	if _, err := normalizeServices(strings.Join(many, ",")); err == nil {
		t.Error("an over-long list passed")
	}
}

// A device's own list wins, then its network's, then the default (web and time).
func TestEffectiveServices(t *testing.T) {
	if got := effectiveServices(nil, nil); got != "web,time" {
		t.Fatalf("default: %q", got)
	}
	n := &Network{Services: "web"}
	if got := effectiveServices(n, &Client{}); got != "web" {
		t.Fatalf("network: %q", got)
	}
	if got := effectiveServices(n, &Client{Services: "ssh"}); got != "ssh" {
		t.Fatalf("device: %q", got)
	}
}

// Opening something new needs a step-up; taking something away doesn't.
func TestWidens(t *testing.T) {
	for _, c := range []struct {
		old, new string
		want     bool
	}{
		{"web,time", "web", false},
		{"web", "web,time", true},
		{"web", "tcp:443", false},
		{"web", "tcp:8443", true},
		{"web", "all", true},
		{"all", "web,ssh", false},
		{"all", "all,smtp", true},
		{"all,smtp", "all", false},
		{"web", "smtp", true},
	} {
		if got := widens(c.old, c.new); got != c.want {
			t.Errorf("widens(%q, %q) = %v", c.old, c.new, got)
		}
	}
}

// Only the listed ports go out; "everything" still keeps direct mail shut unless it is allowed;
// a device with nothing listed gets no way out.
func TestReachabilityServices(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true}}
	dev := func(ip, mac, list string) devicePolicy {
		return devicePolicy{IP: ip, MAC: mac, Internet: true, Out: portsOf(list)}
	}
	pol := map[int64]netPolicy{1: {Devices: []devicePolicy{
		dev("10.20.20.51", "02:00:00:00:00:51", "web,time"),
		dev("10.20.20.52", "02:00:00:00:00:52", "all"),
		dev("10.20.20.53", "02:00:00:00:00:53", "all,smtp"),
		dev("10.20.20.54", "02:00:00:00:00:54", "ssh,smtp,tcp:8883,udp:5000"),
		dev("10.20.20.55", "02:00:00:00:00:55", "nonsense"),
	}}}
	got := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{})
	from := func(ip, mac string) string {
		return `iifname "ens19" ether saddr ` + mac + ` ip saddr ` + ip + ` oifname "eth0"`
	}
	for _, want := range []string{
		from("10.20.20.51", "02:00:00:00:00:51") + ` tcp dport { 80, 443 } accept`,
		from("10.20.20.51", "02:00:00:00:00:51") + ` udp dport { 123, 443 } accept`,
		from("10.20.20.52", "02:00:00:00:00:52") + ` tcp dport 25 drop`,
		from("10.20.20.52", "02:00:00:00:00:52") + ` accept`,
		from("10.20.20.53", "02:00:00:00:00:53") + ` accept`,
		from("10.20.20.54", "02:00:00:00:00:54") + ` tcp dport { 22, 25, 8883 } accept`,
		from("10.20.20.54", "02:00:00:00:00:54") + ` udp dport 5000 accept`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, from("10.20.20.53", "02:00:00:00:00:53")+` tcp dport 25 drop`) {
		t.Fatalf("direct mail allowed, yet dropped:\n%s", got)
	}
	if strings.Contains(got, "saddr 10.20.20.55 oifname") || strings.Contains(got, "nonsense") {
		t.Fatalf("a device with nothing valid listed must get no way out:\n%s", got)
	}
	if strings.Contains(got, from("10.20.20.51", "02:00:00:00:00:51")+" accept") {
		t.Fatalf("a device with services must not get every port:\n%s", got)
	}
	// The 25 drop comes before the everything-accept.
	if strings.Index(got, from("10.20.20.52", "02:00:00:00:00:52")+` tcp dport 25 drop`) > strings.Index(got, from("10.20.20.52", "02:00:00:00:00:52")+` accept`) {
		t.Fatalf("port 25 must be dropped before the accept:\n%s", got)
	}
	// Taking a service away cuts the device's open connections.
	before := accessOf(nets, pol, "eth0", routeOrigin{})
	pol[1].Devices[0] = dev("10.20.20.51", "02:00:00:00:00:51", "web")
	if lost := lostAccess(before, accessOf(nets, pol, "eth0", routeOrigin{})); !strings.Contains(strings.Join(lost, ","), "10.20.20.51") {
		t.Fatalf("a removed service must cut the device's connections: %v", lost)
	}
}
