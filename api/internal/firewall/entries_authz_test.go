package firewall

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/router"

	_ "github.com/mattn/go-sqlite3"
)

// An operator manages blocks only: re-enabling an allow-rule or a port entry an admin switched
// off, or widening its direction, is as admin-grade as creating it; so is taking one away.
func TestOperatorCantReopenFirewall(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE firewall_entries (id INTEGER PRIMARY KEY, entry_type TEXT, value TEXT,
		action TEXT, direction TEXT DEFAULT 'inbound', essential BOOLEAN DEFAULT 0, enabled BOOLEAN DEFAULT 1);
		INSERT INTO firewall_entries (id, entry_type, value, action, enabled) VALUES
			(1, 'ip', '198.51.100.7', 'allow', 0), (2, 'port', '8080', 'allow', 0), (3, 'ip', '203.0.113.9', 'block', 0)`); err != nil {
		t.Fatal(err)
	}
	s := &Service{db: &database.DB{DB: db}}
	as := func(role, method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		return r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: role, Username: role}))
	}
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"enabled":true}`, http.StatusForbidden},
		{`{"direction":"both"}`, http.StatusForbidden},
	} {
		rr := httptest.NewRecorder()
		s.handleToggleEntry(rr, as("operator", http.MethodPut, "/api/fw/entries/1/toggle", c.body))
		if rr.Code != c.want {
			t.Errorf("operator toggle %s on an allow-rule: %d, want %d", c.body, rr.Code, c.want)
		}
	}
	rr := httptest.NewRecorder()
	s.handleBulkEntries(rr, as("operator", http.MethodPost, "/api/fw/entries/bulk", `{"action":"enable","ids":[3,2]}`))
	if rr.Code != http.StatusForbidden {
		t.Errorf("operator bulk-enabled a port entry: %d", rr.Code)
	}
	if !s.anyOpensFirewall([]int64{1}) || s.anyOpensFirewall([]int64{3}) {
		t.Fatal("allow/port vs block entries misread")
	}

	// Nor take one away: deleting, disabling or bulk-deleting an allow-rule or port entry can cut
	// off a source or a service an admin opened.
	db.Exec(`UPDATE firewall_entries SET enabled = 1`)
	for _, c := range []struct {
		name string
		do   func(*httptest.ResponseRecorder)
	}{
		{"delete an allow-rule", func(rr *httptest.ResponseRecorder) {
			s.handleDeleteEntry(rr, as("operator", http.MethodDelete, "/api/fw/entries/1", ""))
		}},
		{"delete a port entry", func(rr *httptest.ResponseRecorder) {
			s.handleDeleteEntry(rr, as("operator", http.MethodDelete, "/api/fw/entries/2", ""))
		}},
		{"disable an allow-rule", func(rr *httptest.ResponseRecorder) {
			s.handleToggleEntry(rr, as("operator", http.MethodPut, "/api/fw/entries/1/toggle", `{"enabled":false}`))
		}},
		{"bulk delete", func(rr *httptest.ResponseRecorder) {
			s.handleBulkEntries(rr, as("operator", http.MethodPost, "/api/fw/entries/bulk", `{"action":"delete","ids":[3,1]}`))
		}},
		{"bulk disable", func(rr *httptest.ResponseRecorder) {
			s.handleBulkEntries(rr, as("operator", http.MethodPost, "/api/fw/entries/bulk", `{"action":"disable","ids":[2]}`))
		}},
	} {
		rr := httptest.NewRecorder()
		c.do(rr)
		if rr.Code != http.StatusForbidden {
			t.Errorf("operator could %s: %d", c.name, rr.Code)
		}
	}
	var left int
	db.QueryRow(`SELECT COUNT(*) FROM firewall_entries WHERE enabled = 1`).Scan(&left)
	if left != 3 {
		t.Fatalf("%d of 3 entries left enabled", left)
	}
}

// An operator's block can't overwrite an admin's allow-rule with the same address; their own
// blocks stay theirs to delete.
func TestOperatorBlockCantOverwriteAllow(t *testing.T) {
	s := lockoutService(t)
	if _, err := s.db.Exec(`INSERT INTO firewall_entries (entry_type, value, action, protocol, source) VALUES ('ip', '198.51.100.44', 'allow', 'both', 'manual')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Exec(`DELETE FROM firewall_entries WHERE value = '198.51.100.44'`) })
	r := httptest.NewRequest(http.MethodPost, "/api/fw/entries", strings.NewReader(`{"type":"ip","value":"198.51.100.44","action":"block","protocol":"both"}`))
	r = r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: "operator", Username: "operator"}))
	rr := httptest.NewRecorder()
	s.handleCreateEntry(rr, r)
	var action string
	s.db.QueryRow(`SELECT action FROM firewall_entries WHERE value = '198.51.100.44'`).Scan(&action)
	if rr.Code != http.StatusForbidden || action != "allow" {
		t.Fatalf("operator block over an allow-rule: %d, action now %q", rr.Code, action)
	}

	res, err := s.db.Exec(`INSERT INTO firewall_entries (entry_type, value, action, protocol, source) VALUES ('ip', '198.51.100.45', 'block', 'both', 'manual')`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Exec(`DELETE FROM firewall_entries WHERE value = '198.51.100.45'`) })
	id, _ := res.LastInsertId()
	r = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/fw/entries/%d", id), nil)
	r = r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: "operator", Username: "operator"}))
	rr = httptest.NewRecorder()
	s.handleDeleteEntry(rr, r)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("operator deleting a block: %d %s", rr.Code, rr.Body)
	}
}
