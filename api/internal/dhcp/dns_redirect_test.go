package dhcp

import (
	"strings"
	"testing"
)

// Every lookup a device aims at a DNS server on the internet is answered by AdGuard, except
// a device allowed outside DNS (per protocol, by IP + MAC), whose lookups go out; one taking its
// address with another MAC is still answered by AdGuard.
func TestDNSRedirectToAdGuard(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", Enabled: true}}
	dev := func(ip, mac string, internet bool, list string) devicePolicy {
		return devicePolicy{IP: ip, MAC: mac, Internet: internet, Out: portsOf(list)}
	}
	pol := map[int64]netPolicy{1: {Devices: []devicePolicy{
		dev("10.20.20.51", "02:00:00:00:00:51", true, "web,time"),     // default
		dev("10.20.20.52", "02:00:00:00:00:52", true, "web,dns"),      // Outside DNS
		dev("10.20.20.53", "02:00:00:00:00:53", true, "web,udp:53"),   // port 53 by hand, UDP only
		dev("10.20.20.54", "02:00:00:00:00:54", false, "web,dns"),     // Outside DNS but no internet
		dev("10.20.20.55", "02:00:00:00:00:55", true, "all,web,time"), // every port, DNS guarded
	}}}
	got := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{}, "10.8.0.1")
	from := func(ip, mac string) string { return `iifname "ens19" ether saddr ` + mac + ` ip saddr ` + ip }

	gateway := `iifname "ens19" ip daddr 10.20.20.1 meta l4proto { tcp, udp } th dport 53 dnat ip to 10.8.0.1`
	catchAll := `iifname "ens19" ip daddr != @private_ranges meta l4proto { tcp, udp } th dport 53 dnat ip to 10.8.0.1`
	for _, want := range []string{gateway, catchAll,
		from("10.20.20.52", "02:00:00:00:00:52") + ` udp dport 53 accept`,
		from("10.20.20.52", "02:00:00:00:00:52") + ` tcp dport 53 accept`,
		from("10.20.20.53", "02:00:00:00:00:53") + ` udp dport 53 accept`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	// The gateway's own lookups are answered first for everyone, then the exceptions, then the rest.
	g, e, c := strings.Index(got, gateway), strings.Index(got, from("10.20.20.52", "02:00:00:00:00:52")+` udp dport 53 accept`), strings.Index(got, catchAll)
	if g > e || e > c {
		t.Fatalf("order must be gateway, exceptions, catch-all:\n%s", got)
	}
	for _, ip := range []string{"10.20.20.51", "10.20.20.54", "10.20.20.55"} {
		if strings.Contains(got, "ip saddr "+ip+" udp dport 53 accept") || strings.Contains(got, "ip saddr "+ip+" tcp dport 53 accept") {
			t.Fatalf("%s may not skip AdGuard:\n%s", ip, got)
		}
	}
	if strings.Contains(got, "ip saddr 10.20.20.53 tcp dport 53 accept") {
		t.Fatalf("a device with only UDP 53 open must not skip AdGuard over TCP:\n%s", got)
	}
	// An exception is bound to the device's MAC: the address alone never matches it.
	if strings.Contains(got, `iifname "ens19" ip saddr 10.20.20.52 udp dport 53 accept`) {
		t.Fatalf("an exception without the MAC:\n%s", got)
	}

	// Without a valid server address nothing is redirected (and nothing let past either).
	if out := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{}, ""); strings.Contains(out, "dport 53 dnat") || strings.Contains(out, "udp dport 53 accept") || strings.Contains(out, "tcp dport 53 accept") {
		t.Fatalf("no server address, yet DNS rules:\n%s", out)
	}
}
