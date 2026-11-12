package helper

import (
	"os"
	"path/filepath"
	"testing"
)

// essentialFrom loads the essential ports from file, keyed by port, without the SSH and API ports.
func essentialFrom(t *testing.T, file string) map[int]EssentialPort {
	t.Helper()
	t.Setenv("ESSENTIAL_PORTS_FILE", file)
	t.Setenv("API_PORT", "")
	ssh := map[int]bool{}
	for _, p := range SSHPorts() {
		ssh[p] = true
	}
	got := map[int]EssentialPort{}
	for _, p := range BuildEssentialPorts() {
		if !ssh[p.Port] {
			got[p.Port] = p
		}
	}
	return got
}

// A port may be listed as private; a scope that is neither public nor private skips the entry.
func TestEssentialPortScope(t *testing.T) {
	file := filepath.Join(t.TempDir(), "essential.json")
	if err := os.WriteFile(file, []byte(`[
		{"port": 18083, "proto": "tcp", "service": "Dashboard", "scope": "private"},
		{"port": 18443, "proto": "tcp", "service": "Web", "scope": "public"},
		{"port": 18444, "proto": "tcp", "service": "Plain"},
		{"port": 18445, "proto": "tcp", "service": "Typo", "scope": "open"}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := essentialFrom(t, file)
	if !got[18083].Private || got[18443].Private || got[18444].Private {
		t.Fatalf("scopes read wrong: %+v", got)
	}
	if _, ok := got[18445]; ok {
		t.Fatal("an entry with an unknown scope must be skipped")
	}
}

// The shipped list opens nothing that has no reason to be public: no direct headscale port, no
// Traefik dashboard (it is on loopback only), and the AdGuard UI starts private.
func TestShippedEssentialPorts(t *testing.T) {
	got := essentialFrom(t, filepath.Join("..", "..", "configs", "essential-ports.json"))
	for _, port := range []int{8080, 8443} {
		if _, ok := got[port]; ok {
			t.Errorf("port %d must not be an essential port", port)
		}
	}
	if p, ok := got[8083]; !ok || !p.Private {
		t.Errorf("the AdGuard UI must be an essential private port: %+v", p)
	}
}
