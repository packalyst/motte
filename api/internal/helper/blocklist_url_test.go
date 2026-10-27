package helper

import (
	"strings"
	"testing"
)

func TestSanitizeBlocklistURLAcceptsPublicHTTPS(t *testing.T) {
	for in, want := range map[string]string{
		"https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
		"  https://big.oisd.nl  ":    "https://big.oisd.nl",
		"https://203.0.113.10/x.txt": "https://203.0.113.10/x.txt",
	} {
		got, err := SanitizeBlocklistURL(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
}

// Nothing that points at this server, the private or VPN networks, or carries a login gets through.
func TestSanitizeBlocklistURLRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"http://lists.example.com/x.txt",  // not https
		"file:///etc/passwd",              // a local file
		"/etc/passwd",                     // a path
		"https://user:pass@example.com/x", // a login
		"https://localhost/x",
		"https://LOCALHOST./x",
		"https://api.localhost/x",
		"https://127.0.0.1:8099/api",
		"https://[::1]/x",
		"https://[::ffff:127.0.0.1]/x",
		"https://10.8.0.1/x",
		"https://192.168.1.1/x",
		"https://172.16.0.5/x",
		"https://100.64.0.1/x", // Tailscale / Headscale overlay
		"https://169.254.169.254/latest/meta-data",
		"https://0.0.0.0/x",
		"https:///x",
		"https://example.com/" + strings.Repeat("a", 2048),
	} {
		if got, err := SanitizeBlocklistURL(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}
