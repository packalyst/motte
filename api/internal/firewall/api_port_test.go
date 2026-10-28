package firewall

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"api/internal/helper"
)

// TestAPIPortPinnedPrivate: the panel API port is seeded (and kept) private, can't be made public
// through the scope endpoint, and shows as pinned in the Ports list; other ports still toggle.
func TestAPIPortPinnedPrivate(t *testing.T) {
	t.Setenv("API_PORT", "18081")
	s := lockoutService(t)
	s.config.EssentialPorts = []helper.EssentialPort{{Port: 18081, Protocol: "tcp", Service: "Panel API"}}

	// An existing row that says public (an old install, a restored backup) is put back to private.
	if _, err := s.db.Exec(`INSERT INTO firewall_entries (entry_type, value, action, direction, protocol, source, essential, scope, enabled)
		VALUES ('port', '18081', 'allow', 'inbound', 'tcp', 'system', 1, 'public', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureEssentialPorts(); err != nil {
		t.Fatal(err)
	}
	scope := func(port string) string {
		var v string
		s.db.QueryRow(`SELECT scope FROM firewall_entries WHERE entry_type = 'port' AND value = ?`, port).Scan(&v)
		return v
	}
	if got := scope("18081"); got != "private" {
		t.Fatalf("API port scope %q after seeding, want private", got)
	}

	setScope := func(port, to string) int {
		rec := httptest.NewRecorder()
		s.handleSetPortScope(rec, adminReq("/api/fw/ports/scope", `{"port":`+port+`,"protocol":"tcp","scope":"`+to+`"}`))
		return rec.Code
	}
	if code := setScope("18081", "public"); code != http.StatusBadRequest || scope("18081") != "private" {
		t.Errorf("making the API port public: status %d, scope %q; want 400 and private", code, scope("18081"))
	}

	if _, err := s.db.Exec(`INSERT INTO firewall_entries (entry_type, value, action, direction, protocol, source, enabled)
		VALUES ('port', '2222', 'allow', 'inbound', 'tcp', 'manual', 1)`); err != nil {
		t.Fatal(err)
	}
	if code := setScope("2222", "private"); code != http.StatusOK || scope("2222") != "private" {
		t.Errorf("another port: status %d, scope %q; want 200 and private", code, scope("2222"))
	}

	rec := httptest.NewRecorder()
	s.handleGetPorts(rec, httptest.NewRequest(http.MethodGet, "/api/fw/ports", nil))
	var ports []PortEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &ports); err != nil {
		t.Fatal(err)
	}
	for _, p := range ports {
		if want := p.Port == 18081; p.Pinned != want || (want && p.Scope != "private") {
			t.Errorf("Ports list entry %+v: pinned %v, want %v (and private)", p, p.Pinned, want)
		}
	}
}
