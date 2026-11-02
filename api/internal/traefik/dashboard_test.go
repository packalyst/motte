package traefik

import "testing"

// The dashboard's address comes only from the environment: a missing or invalid value is refused,
// never replaced by a guessed address.
func TestDashboardAddress(t *testing.T) {
	for _, c := range []struct {
		port, ip string
		public   bool
		want     string // "" = refused
	}{
		{"8081", "172.18.0.5", false, "172.18.0.5:8081"},
		{"8081", "", true, ":8081"},
		{"8081", "", false, ""},
		{"8081", "not-an-ip", false, ""},
		{"8081", "0.0.0.0", false, ""},
		{"8081", "fd00::5", false, ""},
		{"", "172.18.0.5", false, ""},
		{"", "", true, ""},
		{"0", "172.18.0.5", false, ""},
		{"70000", "172.18.0.5", true, ""},
		{"80x", "172.18.0.5", false, ""},
	} {
		t.Setenv("TRAEFIK_PORT", c.port)
		t.Setenv("TRAEFIK_CONTAINER_IP", c.ip)
		got, err := dashboardAddress(c.public)
		if c.want == "" {
			if err == nil {
				t.Errorf("port %q ip %q public %v: got %q, want refused", c.port, c.ip, c.public, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("port %q ip %q public %v: got %q, %v; want %q", c.port, c.ip, c.public, got, err, c.want)
		}
	}
}
