package firewall

import (
	"database/sql"
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
// off, or widening its direction, is as admin-grade as creating it. Blocks stay theirs.
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
}
