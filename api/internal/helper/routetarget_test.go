package helper

import (
	"net/netip"
	"testing"
)

// A route can't point at what only this server reaches: loopback, link-local, unspecified,
// multicast, the panel's Docker network, or the panel's own services on any of its addresses.
// Other addresses, and other ports on this server, stay routable.
func TestCheckRouteTarget(t *testing.T) {
	t.Setenv("DOCKER_SUBNET", "172.30.0.0/24")
	t.Setenv("API_PORT", "18081")
	t.Setenv("ADGUARD_PORT", "18083")
	t.Setenv("TRAEFIK_PORT", "18080")
	prev := hostAddrs
	hostAddrs = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("10.8.0.1")}
	}
	t.Cleanup(func() { hostAddrs = prev })

	for _, c := range []struct {
		ip   string
		port int
		ok   bool
	}{
		{"127.0.0.1", 3000, false},
		{"169.254.169.254", 80, false},
		{"0.0.0.0", 80, false},
		{"224.0.0.1", 80, false},
		{"172.30.0.2", 80, false},
		{"10.8.0.1", 18081, false},
		{"203.0.113.5", 18083, false},
		{"203.0.113.5", 18080, false},
		{"not-an-ip", 80, false},
		{"fd00::1", 80, false},
		{"10.8.0.1", 3000, true},     // an app on this server
		{"192.168.1.20", 8080, true}, // a machine on a LAN
		{"10.8.128.1", 80, true},     // a LAN device's VPN address
	} {
		if err := CheckRouteTarget(c.ip, c.port); (err == nil) != c.ok {
			t.Errorf("%s:%d: ok=%v, got %v", c.ip, c.port, c.ok, err)
		}
	}
}

func TestSystemDomains(t *testing.T) {
	t.Setenv("SSL_DOMAIN", "Panel.Example.com")
	t.Setenv("ADMIN_DOMAIN", "panel.example.com")
	t.Setenv("PROXY_DOMAIN", "proxy.example.com")
	got := SystemDomains()
	if len(got) != 2 || got[0] != "panel.example.com" || got[1] != "proxy.example.com" {
		t.Fatalf("got %v", got)
	}
}
