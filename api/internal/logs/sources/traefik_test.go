package sources

import "testing"

// The access-log visitor: Cloudflare's CF-Connecting-IP only when the request came from a
// Cloudflare edge; otherwise the address that connected, whatever headers it sent.
func TestRealClientIP(t *testing.T) {
	for _, c := range []struct {
		host, cf, want string
	}{
		{"104.16.0.1", "203.0.113.5", "203.0.113.5"}, // via Cloudflare
		{"104.16.0.1", "", "104.16.0.1"},
		{"104.16.0.1", "not-an-ip", "104.16.0.1"},
		{"192.0.2.9", "203.0.113.5", "192.0.2.9"}, // direct: a forged header is ignored
		{"10.8.0.4", "203.0.113.5", "10.8.0.4"},
	} {
		if got := realClientIP(&TraefikLogEntry{ClientHost: c.host, RequestCFConnectingIP: c.cf}); got != c.want {
			t.Errorf("host %s cf %q: %s, want %s", c.host, c.cf, got, c.want)
		}
	}
}
