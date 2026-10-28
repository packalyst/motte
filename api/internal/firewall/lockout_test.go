package firewall

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/router"
)

// Synthetic addresses only: the server is 203.0.113.5 and the admin calls from 198.51.100.20.
func lockoutService(t *testing.T) *Service {
	t.Helper()
	db, err := database.Init(t.TempDir()) // the real schema; shared across this package's tests
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM firewall_entries`); err != nil {
		t.Fatal(err)
	}
	return &Service{db: db, config: Config{ServerIP: "203.0.113.5"}}
}

func adminReq(path, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.20:40000"
	return r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: "admin", Username: "admin"}))
}

func storedValues(t *testing.T, s *Service) map[string]bool {
	t.Helper()
	rows, err := s.db.Query(`SELECT value FROM firewall_entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		got[v] = true
	}
	return got
}

// A block that would cut the panel off is refused on the single-entry path, ranges included.
func TestCreateRefusesLockout(t *testing.T) {
	s := lockoutService(t)
	for _, c := range []struct {
		typ, value string
		want       int
	}{
		{"range", "0.0.0.0/1", http.StatusBadRequest},      // half the internet
		{"range", "8.0.0.0/5", http.StatusBadRequest},      // wider than /8, and holds 10/8
		{"range", "10.0.0.0/8", http.StatusBadRequest},     // the VPN
		{"ip", "10.8.0.5", http.StatusBadRequest},          // one VPN client
		{"ip", "100.100.100.100", http.StatusBadRequest},   // the overlay
		{"range", "192.168.0.0/15", http.StatusBadRequest}, // starts private, spills public
		{"range", "203.0.113.0/24", http.StatusBadRequest}, // this server
		{"ip", "198.51.100.0/24", http.StatusBadRequest},   // the caller (an ip typed as a CIDR)
		{"range", "192.0.2.0/24", http.StatusOK},
		{"ip", "192.0.2.200", http.StatusOK},
	} {
		rr := httptest.NewRecorder()
		s.handleCreateEntry(rr, adminReq("/api/fw/entries", `{"type":"`+c.typ+`","value":"`+c.value+`","action":"block"}`))
		if rr.Code != c.want {
			t.Errorf("block %s %s: %d, want %d (%s)", c.typ, c.value, rr.Code, c.want, rr.Body.String())
		}
	}
	if got := storedValues(t, s); len(got) != 2 || !got["192.0.2.0/24"] || !got["192.0.2.200"] {
		t.Errorf("stored %v", got)
	}
}

// The /8 floor holds for allow-rules too (0.0.0.0/1 + 128.0.0.0/1 would open everything);
// allowing private space stays possible, as before.
func TestAllowWiderThanSlash8Refused(t *testing.T) {
	s := lockoutService(t)
	for value, want := range map[string]int{"0.0.0.0/0": http.StatusBadRequest, "0.0.0.0/1": http.StatusBadRequest, "10.0.0.0/8": http.StatusOK} {
		rr := httptest.NewRecorder()
		s.handleCreateEntry(rr, adminReq("/api/fw/entries", `{"type":"ip","value":"`+value+`","action":"allow"}`))
		if rr.Code != want {
			t.Errorf("allow %s: %d, want %d (%s)", value, rr.Code, want, rr.Body.String())
		}
	}
}

// Bulk create and list import skip the same rows instead of storing them.
func TestBulkAndImportSkipLockout(t *testing.T) {
	s := lockoutService(t)
	rr := httptest.NewRecorder()
	s.handleBulkEntries(rr, adminReq("/api/fw/entries/bulk", `{"action":"create","entries":[
		{"type":"range","value":"0.0.0.0/1"},{"type":"range","value":"128.0.0.0/1"},
		{"type":"ip","value":"198.51.100.20"},{"type":"range","value":"192.0.2.0/24"}]}`))
	var bulk struct{ Created, Skipped int }
	json.Unmarshal(rr.Body.Bytes(), &bulk)
	if rr.Code != http.StatusOK || bulk.Created != 1 || bulk.Skipped != 3 {
		t.Fatalf("bulk: %d %s", rr.Code, rr.Body.String())
	}

	blocklistSources["lockout-test"] = BlocklistSource{Type: "static", Ranges: []string{
		"0.0.0.0/8", "224.0.0.0/3", "10.0.0.0/8", "203.0.113.5", "198.51.100.0/24", "2001:db8::/32", "junk", "", "192.0.2.128/25", "198.18.0.1"}}
	t.Cleanup(func() { delete(blocklistSources, "lockout-test") })
	rr = httptest.NewRecorder()
	s.handleImportEntries(rr, adminReq("/api/fw/entries/import", `{"source":"lockout-test"}`))
	var imp struct{ Added, Skipped int }
	json.Unmarshal(rr.Body.Bytes(), &imp)
	if rr.Code != http.StatusOK || imp.Added != 2 || imp.Skipped != 8 {
		t.Fatalf("import: %d %s", rr.Code, rr.Body.String())
	}
	if got := storedValues(t, s); len(got) != 3 || !got["192.0.2.128/25"] || !got["198.18.0.1"] {
		t.Errorf("stored %v", got)
	}
}

// Auto-ban (a jail reading log lines) never bans the VPN, loopback, this server or IPv6.
func TestAutoBanSkipsProtected(t *testing.T) {
	s := lockoutService(t)
	for _, ip := range []string{"10.8.0.9", "127.0.0.1", "203.0.113.5", "2001:db8::9", "192.0.2.50"} {
		s.blockIP(ip, "sshd", "test", 0)
	}
	if got := storedValues(t, s); len(got) != 1 || !got["192.0.2.50"] {
		t.Errorf("auto-banned %v, want only 192.0.2.50", got)
	}
}

func TestBlockLockoutErrorIgnoresNonAddresses(t *testing.T) {
	s := lockoutService(t)
	for _, typ := range []string{"country", "asn", "port"} {
		if err := s.blockLockoutError(typ, "anything", "198.51.100.20"); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
}
