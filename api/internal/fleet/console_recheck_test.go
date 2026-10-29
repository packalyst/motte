package fleet

import (
	"net/http"
	"testing"
	"time"

	"api/internal/auth"
	"api/internal/router"
)

// TestConsoleAccess: the rules an open console is re-checked against — the session must still
// resolve, be unlocked and carry the operator role, the machine must stay in scope and keep its
// console enabled.
func TestConsoleAccess(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "box", false)
	if _, err := svc.db.Exec(`UPDATE fleet_machines SET console_enabled = 1 WHERE id = 'box'`); err != nil {
		t.Fatal(err)
	}
	principals := map[string]*router.Principal{
		"op":       {UserID: 1, Role: auth.RoleOperator},
		"locked":   {UserID: 1, Role: auth.RoleOperator, Locked: true},
		"viewer":   {UserID: 1, Role: auth.RoleViewer},
		"otherbox": {UserID: 1, Role: auth.RoleOperator, ScopeKind: auth.ScopeHost, ScopeValues: "elsewhere"},
	}
	router.SetAuthResolver(func(token string) (*router.Principal, bool) { p, ok := principals[token]; return p, ok })
	t.Cleanup(func() { router.SetAuthResolver(nil) })

	for token, want := range map[string]int{
		"op": 0, "revoked": http.StatusUnauthorized, "locked": http.StatusUnauthorized,
		"viewer": http.StatusForbidden, "otherbox": http.StatusForbidden,
	} {
		if _, _, code, _ := svc.consoleAccess(token, "box"); code != want {
			t.Errorf("%s: code %d, want %d", token, code, want)
		}
	}
	if _, _, code, _ := svc.consoleAccess("op", "missing"); code != http.StatusNotFound {
		t.Errorf("unknown machine: code %d, want 404", code)
	}
	if _, err := svc.db.Exec(`UPDATE fleet_machines SET console_enabled = 0 WHERE id = 'box'`); err != nil {
		t.Fatal(err)
	}
	if _, _, code, _ := svc.consoleAccess("op", "box"); code != http.StatusForbidden {
		t.Errorf("console switched off: code %d, want 403", code)
	}
}

// TestRecheckUntil: the first failed check cuts once and ends the watch; closing stop ends it too.
func TestRecheckUntil(t *testing.T) {
	ok := true
	cut := make(chan string, 2)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		recheckUntil(5*time.Millisecond, stop, func() string {
			if ok {
				ok = false
				return ""
			}
			return "insufficient role"
		}, func(reason string) { cut <- reason })
		close(done)
	}()
	select {
	case r := <-cut:
		if r != "insufficient role" {
			t.Errorf("cut reason %q", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a failed check didn't cut")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watch kept running after cutting")
	}
	close(stop)

	stop2 := make(chan struct{})
	done2 := make(chan struct{})
	go func() { recheckUntil(time.Hour, stop2, func() string { return "x" }, func(string) {}); close(done2) }()
	close(stop2)
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("closing stop didn't end the watch")
	}
}
