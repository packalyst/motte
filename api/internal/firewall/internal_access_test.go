package firewall

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInternalCallerAllowed(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       bool
	}{
		{"loopback", "127.0.0.1:5000", nil, true},
		{"ipv6 loopback", "[::1]:5000", nil, true},
		{"docker bridge (private)", "172.18.0.5:41000", nil, true},
		{"rfc1918 10/8", "10.0.0.9:41000", nil, true},
		{"public source refused", "203.0.113.7:41000", nil, false},
		{"private but proxied refused", "172.18.0.5:41000", map[string]string{"X-Forwarded-For": "1.2.3.4"}, false},
		{"private but cf-proxied refused", "172.18.0.5:41000", map[string]string{"CF-Connecting-IP": "1.2.3.4"}, false},
		{"bare ip no port", "127.0.0.1", nil, true},
		{"garbage addr refused", "not-an-ip", nil, false},
	}
	for _, c := range cases {
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
