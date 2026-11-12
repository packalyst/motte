package firewall

import (
	"testing"

	"api/internal/helper"
)

// TestStaleEssentialPortsDemoted: a port the panel added that is no longer essential (an old SSH
// port from a migrated database) stays open but becomes removable; a current essential port that
// was demoted is essential again; Docker-discovered ports are left alone.
func TestStaleEssentialPortsDemoted(t *testing.T) {
	s := lockoutService(t)
	s.config.EssentialPorts = []helper.EssentialPort{{Port: 2222, Protocol: "tcp", Service: "SSH"}}
	for _, row := range []struct {
		port, source string
		essential    int
	}{
		{"2297", "system", 1}, // old server's SSH port
		{"2222", "system", 0}, // current SSH port, demoted earlier (detection failed once)
		{"9000", "docker", 1}, // published by a container
	} {
		if _, err := s.db.Exec(`INSERT INTO firewall_entries (entry_type, value, action, direction, protocol, source, essential, enabled)
			VALUES ('port', ?, 'allow', 'inbound', 'tcp', ?, ?, 1)`, row.port, row.source, row.essential); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ensureEssentialPorts(); err != nil {
		t.Fatal(err)
	}
	for port, want := range map[string]bool{"2297": false, "2222": true, "9000": true} {
		var essential, enabled bool
		if err := s.db.QueryRow(`SELECT essential, enabled FROM firewall_entries WHERE entry_type = 'port' AND value = ?`, port).Scan(&essential, &enabled); err != nil {
			t.Fatalf("port %s: %v", port, err)
		}
		if essential != want || !enabled {
			t.Errorf("port %s: essential %v enabled %v, want essential %v and still open", port, essential, enabled, want)
		}
	}
}

// TestPrivateEssentialPortStartsPrivate: an essential port listed as private is created private,
// and an admin's later choice (made public) is kept on the next start.
func TestPrivateEssentialPortStartsPrivate(t *testing.T) {
	s := lockoutService(t)
	s.config.EssentialPorts = []helper.EssentialPort{
		{Port: 18083, Protocol: "tcp", Service: "Dashboard", Private: true},
		{Port: 18443, Protocol: "tcp", Service: "Web"},
	}
	scope := func(port string) string {
		t.Helper()
		var sc string
		if err := s.db.QueryRow(`SELECT scope FROM firewall_entries WHERE entry_type = 'port' AND value = ?`, port).Scan(&sc); err != nil {
			t.Fatalf("port %s: %v", port, err)
		}
		return sc
	}
	if err := s.ensureEssentialPorts(); err != nil {
		t.Fatal(err)
	}
	if got := scope("18083"); got != "private" {
		t.Fatalf("private essential port created %s", got)
	}
	if got := scope("18443"); got != "public" {
		t.Fatalf("public essential port created %s", got)
	}
	if _, err := s.db.Exec(`UPDATE firewall_entries SET scope = 'public' WHERE value = '18083'`); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureEssentialPorts(); err != nil {
		t.Fatal(err)
	}
	if got := scope("18083"); got != "public" {
		t.Fatalf("the admin's choice was overwritten: %s", got)
	}
}
