package firewall

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Only Traefik's own address may use /internal/*: no other private address (a VPN client, a LAN
// device, the host itself), nothing at all when the address isn't configured.
func TestInternalCallerAllowed(t *testing.T) {
	cases := []struct {
		name       string
		traefik    string
		remoteAddr string
		headers    map[string]string
		want       bool
	}{
		{"traefik", "172.18.0.3", "172.18.0.3:41000", nil, true},
		{"traefik, bare ip no port", "172.18.0.3", "172.18.0.3", nil, true},
		{"another container on the bridge", "172.18.0.3", "172.18.0.5:41000", nil, false},
		{"vpn client", "172.18.0.3", "10.8.0.9:41000", nil, false},
		{"lan device", "172.18.0.3", "192.168.50.20:41000", nil, false},
		{"loopback", "172.18.0.3", "127.0.0.1:5000", nil, false},
		{"ipv6 loopback", "172.18.0.3", "[::1]:5000", nil, false},
		{"public source", "172.18.0.3", "203.0.113.7:41000", nil, false},
		{"traefik but proxied", "172.18.0.3", "172.18.0.3:41000", map[string]string{"X-Forwarded-For": "198.51.100.4"}, false},
		{"traefik but cf-proxied", "172.18.0.3", "172.18.0.3:41000", map[string]string{"CF-Connecting-IP": "198.51.100.4"}, false},
		{"no traefik address configured", "", "172.18.0.3:41000", nil, false},
		{"garbage addr", "172.18.0.3", "not-an-ip", nil, false},
	}
	for _, c := range cases {
		t.Setenv("TRAEFIK_CONTAINER_IP", c.traefik)
		r := httptest.NewRequest(http.MethodGet, "/internal/blocklist", nil)
		r.RemoteAddr = c.remoteAddr
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		if got := internalCallerAllowed(r); got != c.want {
			t.Errorf("%s: internalCallerAllowed = %v, want %v", c.name, got, c.want)
		}
	}
}
