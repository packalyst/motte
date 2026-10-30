package headscale

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/router"
)

// A device delete goes to Headscale first: while Headscale refuses it, the panel keeps the
// device's row and what hangs off it (here an ACL rule), for the single-device and the user delete
// alike; once Headscale deletes it, the panel forgets it.
func TestDeleteNodeHeadscaleFirst(t *testing.T) {
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, _ := database.GetDB()
	for _, q := range []string{
		`INSERT INTO vpn_clients (id, name, ip, type, external_id) VALUES (901, 'laptop', '100.64.0.7', 'headscale', '7')`,
		`INSERT INTO vpn_clients (id, name, ip, type, external_id) VALUES (902, 'desk', '100.64.0.8', 'headscale', '8')`,
		`INSERT INTO vpn_acl_rules (source_client_id, target_client_id) VALUES (901, 902)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string) (n int) { db.QueryRow(q).Scan(&n); return }
	kept := func(when string) {
		t.Helper()
		if count(`SELECT COUNT(*) FROM vpn_clients WHERE id = 901`) != 1 || count(`SELECT COUNT(*) FROM vpn_acl_rules`) != 1 {
			t.Fatalf("%s: the device's records were dropped", when)
		}
	}

	posted := fakeHeadscale(t)
	router.SetStepUpFunc(func(http.ResponseWriter, *http.Request) bool { return true })
	t.Cleanup(func() { router.SetStepUpFunc(nil); refuseNodeDeletes.Store(false) })
	s := &Service{}
	call := func(h http.HandlerFunc, path string) int {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodDelete, path, strings.NewReader(`{}`)))
		return rec.Code
	}

	refuseNodeDeletes.Store(true)
	if code := call(s.handleDeleteNode, "/api/hs/nodes/7"); code != http.StatusBadGateway {
		t.Fatalf("refused device delete: %d, want 502", code)
	}
	kept("refused device delete")
	if code := call(s.handleDeleteUser, "/api/hs/users/alice"); code != http.StatusBadGateway || len(*posted) != 0 {
		t.Fatalf("refused user delete: %d, sent %v (the user must not be deleted)", code, *posted)
	}
	kept("refused user delete")

	refuseNodeDeletes.Store(false)
	if code := call(s.handleDeleteNode, "/api/hs/nodes/7"); code != http.StatusOK {
		t.Fatalf("device delete: %d", code)
	}
	if count(`SELECT COUNT(*) FROM vpn_clients WHERE id = 901`) != 0 || count(`SELECT COUNT(*) FROM vpn_acl_rules`) != 0 {
		t.Fatal("a deleted device's records must go")
	}
	if count(`SELECT COUNT(*) FROM vpn_clients WHERE id = 902`) != 1 {
		t.Fatal("another device's row was touched")
	}
}
