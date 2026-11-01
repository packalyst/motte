package dhcp

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Lists are validated and kept in one order; port 25 only through Direct mail; anything unknown
// is refused.
func TestNormalizeServices(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{" time , WEB,web ", "web,time"},
		{"udp:5000,tcp:8883,ssh,tcp:443", "ssh,tcp:443,tcp:8883,udp:5000"},
		{"all,smtp", "smtp,all"},
		{"all,web,tcp:8883", "web,all"}, // custom ports mean nothing under "all"
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
	if _, err := normalizeServices(strings.Join(many[:maxServiceEntries], ",")); err != nil {
		t.Errorf("a list at the limit was refused: %v", err)
	}
	// A huge list is refused at once, without reading every entry (it used to take minutes).
	huge := strings.Repeat("tcp:1,", 200000)
	start := time.Now()
	if _, err := normalizeServices(huge); err == nil {
		t.Error("a huge list passed")
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("refusing a huge list took %v", d)
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
		{"all", "web,ssh", true},          // "all" alone keeps every service shut, web and ssh too
		{"all,web,ssh", "web,ssh", false}, // the services stay, every other port goes
		{"all", "all,smtp", true},
		{"all", "all,dns", true},
		{"web", "dns", true},
		{"all,smtp", "all", false},
		{"all", "tcp:8883", false}, // 8883 was open as one of the other ports
		{"all", "tcp:443", true},   // 443 belongs to Web, which "all" alone keeps shut
		{"web", "smtp", true},
	} {
		if got := widens(c.old, c.new); got != c.want {
			t.Errorf("widens(%q, %q) = %v", c.old, c.new, got)
		}
	}
}

// Only the listed ports go out; "all" opens every port except the services not ticked (direct
// mail included); a device with nothing listed gets no way out.
func TestReachabilityServices(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true}}
	dev := func(ip, mac, list string) devicePolicy {
		return devicePolicy{IP: ip, MAC: mac, Internet: true, Out: portsOf(list)}
	}
	pol := map[int64]netPolicy{1: {Devices: []devicePolicy{
		dev("10.20.20.51", "02:00:00:00:00:51", "web,time"),
		dev("10.20.20.52", "02:00:00:00:00:52", "all"),
		dev("10.20.20.53", "02:00:00:00:00:53", "all,smtp,web"),
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
		from("10.20.20.52", "02:00:00:00:00:52") + ` tcp dport { 22, 25, 53, 80, 443, 465, 587, 853, 993, 995 } drop`,
		from("10.20.20.52", "02:00:00:00:00:52") + ` udp dport { 53, 123, 443, 853 } drop`,
		from("10.20.20.52", "02:00:00:00:00:52") + ` accept`,
		from("10.20.20.53", "02:00:00:00:00:53") + ` tcp dport { 22, 53, 465, 587, 853, 993, 995 } drop`,
		from("10.20.20.53", "02:00:00:00:00:53") + ` udp dport { 53, 123, 853 } drop`,
		from("10.20.20.53", "02:00:00:00:00:53") + ` accept`,
		from("10.20.20.54", "02:00:00:00:00:54") + ` tcp dport { 22, 25, 8883 } accept`,
		from("10.20.20.54", "02:00:00:00:00:54") + ` udp dport 5000 accept`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, from("10.20.20.53", "02:00:00:00:00:53")+` tcp dport { 22, 25,`) {
		t.Fatalf("direct mail allowed, yet dropped:\n%s", got)
	}
	if strings.Contains(got, "saddr 10.20.20.55 oifname") || strings.Contains(got, "nonsense") {
		t.Fatalf("a device with nothing valid listed must get no way out:\n%s", got)
	}
	if strings.Contains(got, from("10.20.20.51", "02:00:00:00:00:51")+" accept") {
		t.Fatalf("a device with services must not get every port:\n%s", got)
	}
	// The guarded ports are dropped before the every-port accept.
	if strings.Index(got, from("10.20.20.52", "02:00:00:00:00:52")+` tcp dport {`) > strings.Index(got, from("10.20.20.52", "02:00:00:00:00:52")+` accept`) {
		t.Fatalf("guarded ports must be dropped before the accept:\n%s", got)
	}
	// Under "all", taking a service away guards its ports again and cuts the open connections.
	pol[1].Devices[2] = dev("10.20.20.53", "02:00:00:00:00:53", "all,web,smtp")
	allBefore := accessOf(nets, pol, "eth0", routeOrigin{})
	pol[1].Devices[2] = dev("10.20.20.53", "02:00:00:00:00:53", "all,smtp")
	if lost := lostAccess(allBefore, accessOf(nets, pol, "eth0", routeOrigin{})); !strings.Contains(strings.Join(lost, ","), "10.20.20.53") {
		t.Fatalf("guarding a service again must cut the device's connections: %v", lost)
	}
	// Taking a service away cuts the device's open connections.
	before := accessOf(nets, pol, "eth0", routeOrigin{})
	pol[1].Devices[0] = dev("10.20.20.51", "02:00:00:00:00:51", "web")
	if lost := lostAccess(before, accessOf(nets, pol, "eth0", routeOrigin{})); !strings.Contains(strings.Join(lost, ","), "10.20.20.51") {
		t.Fatalf("a removed service must cut the device's connections: %v", lost)
	}
}
