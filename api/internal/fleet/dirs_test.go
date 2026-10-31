package fleet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api/internal/auth"
	"api/internal/router"
)

func TestValidateScanPayloads(t *testing.T) {
	ok := []struct{ ctype, payload string }{
		{"rescan", ``},
		{"rescan", `{}`},
		{"rescan", `{"exclude":["/home/laurs/app","/srv"]}`},
		{"list-dirs", `{"path":"/"}`},
		{"list-dirs", `{"path":"/home"}`},
		{"block", `{"ip":"x"}`}, // other types aren't this check's business
	}
	for _, c := range ok {
		if err := validateCommandPayload(c.ctype, json.RawMessage(c.payload)); err != nil {
			t.Errorf("%s %s: %v", c.ctype, c.payload, err)
		}
	}
	bad := []struct{ ctype, payload string }{
		{"rescan", `{"exclude":["/"]}`},
		{"rescan", `{"exclude":["relative"]}`},
		{"rescan", `{"exclude":["/a/../etc"]}`},
		{"rescan", `{"exclude":["/a\nb"]}`},
		{"rescan", `{"exclude":["/*"]}`},
		{"rescan", `{"exclude":["/home/{a,b}"]}`},
		{"rescan", `{"exclude":["/var"]}`},
		{"rescan", `{"exclude":["/var/lib/dpkg"]}`},
		{"rescan", `{"exclude":["/etc"]}`},
		{"rescan", `{"exclude":"/srv"}`},
		{"rescan", `{"exclude":[` + strings.Repeat(`"/a",`, maxScanExcludes) + `"/a"]}`},
		{"list-dirs", `{"path":""}`},
		{"list-dirs", `{"path":"/x/"}`},
		{"list-dirs", `nope`},
	}
	for _, c := range bad {
		if err := validateCommandPayload(c.ctype, json.RawMessage(c.payload)); err == nil {
			t.Errorf("accepted %s %s", c.ctype, c.payload)
		}
	}
}

// The picker asks the agent, relays its answer, and leaves nothing in the command log.
func TestListDirsRoundTrip(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)

	// a stand-in agent: answer the first list-dirs request it finds
	go func() {
		for range 40 {
			var id string
			if svc.db.QueryRow(`SELECT id FROM fleet_commands WHERE type = 'list-dirs' AND status = 'pending'`).Scan(&id) == nil {
				_, _ = svc.db.Exec(`UPDATE fleet_commands SET status = 'done', result = ? WHERE id = ?`,
					`{"path":"/home","dirs":[{"name":"laurs"}]}`, id)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	w := httptest.NewRecorder()
	r := asOwner(httptest.NewRequest(http.MethodPost, "/api/fleet/dirs", strings.NewReader(`{"machine_id":"m1","path":"/home"}`)))
	svc.handleListDirs(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"laurs"`) {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	var n int
	_ = svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_commands WHERE machine_id = 'm1'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d list-dirs rows left in the command log", n)
	}

	for _, body := range []string{`{"machine_id":"m1","path":"../etc"}`, `{"machine_id":"m1"}`} {
		w = httptest.NewRecorder()
		svc.handleListDirs(w, asOwner(httptest.NewRequest(http.MethodPost, "/api/fleet/dirs", strings.NewReader(body))))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d", body, w.Code)
		}
	}
	addMachine(t, svc, "off", false)
	w = httptest.NewRecorder()
	svc.handleListDirs(w, asOwner(httptest.NewRequest(http.MethodPost, "/api/fleet/dirs", strings.NewReader(`{"machine_id":"off","path":"/"}`))))
	if w.Code != http.StatusConflict {
		t.Errorf("offline machine: got %d", w.Code)
	}
}

// Switching a tool is admin-only on the command endpoint, needs step-up, and names a real tool.
func TestSetToolGuarded(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	as := func(role string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/fleet/command", nil)
		return r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: role, Username: role}))
	}
	w := httptest.NewRecorder()
	if gatePanelInternalCommand(w, as("operator"), "set-tool") || w.Code != http.StatusForbidden {
		t.Fatalf("operator passed the admin gate: %d", w.Code)
	}
	if !gatePanelInternalCommand(httptest.NewRecorder(), as("admin"), "set-tool") {
		t.Fatal("admin blocked")
	}
	rec := httptest.NewRecorder()
	if _, ok := svc.enqueueGuarded(rec, as("owner"), "m1", "set-tool", auth.StepUpCreds{}, json.RawMessage(`{"tool":"crowdsec","enabled":false}`)); ok || rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("no step-up: ok %v status %d", ok, rec.Code)
	}
	for _, p := range []string{`{"tool":"nmap","enabled":true}`, `{"tool":"crowdsec"}`, `{}`} {
		if validateCommandPayload("set-tool", json.RawMessage(p)) == nil {
			t.Errorf("accepted %s", p)
		}
	}
}

// Adding folders for scans to skip takes an admin and a step-up; rescanning with the same list
// or a shorter one stays an operator action.
func TestScanExcludeAddsNeedAdminStepUp(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	if _, err := svc.db.Exec(`UPDATE fleet_machines SET last_report = ? WHERE id = 'm1'`, `{"scan_exclude":["/srv/cache"]}`); err != nil {
		t.Fatal(err)
	}
	as := func(role string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/fleet/command", nil)
		return r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: role, Username: role + "1"}))
	}
	for _, c := range []struct {
		role, payload string
		want          int
	}{
		{"operator", `{}`, 0},                                                   // no list: the saved one stays
		{"operator", `{"exclude":["/srv/cache"]}`, 0},                           // the same list
		{"operator", `{"exclude":[]}`, 0},                                       // scanning more
		{"operator", `{"exclude":["/srv/cache","/opt"]}`, http.StatusForbidden}, // hiding /opt
		{"admin", `{"exclude":["/opt"]}`, 0},                                    // admin: the caller's step-up next
	} {
		_, status, err := svc.guardScanExcludes(as(c.role), "m1", json.RawMessage(c.payload))
		if status != c.want || (c.want == 0) != (err == nil) {
			t.Errorf("%s %s: status %d err %v, want %d", c.role, c.payload, status, err, c.want)
		}
	}
	// The admin's addition is a step-up at the endpoint: without one nothing is queued.
	queued := func() (n int) {
		svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_commands WHERE machine_id = 'm1'`).Scan(&n)
		return
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/fleet/command", strings.NewReader(`{"machine_id":"m1","type":"rescan","payload":{"exclude":["/opt"]}}`))
	svc.handleEnqueueCommand(rec, r.WithContext(as("admin").Context()))
	if rec.Code != http.StatusPreconditionRequired || queued() != 0 {
		t.Fatalf("admin adding a folder without a step-up: status %d, %d queued; want 428, none", rec.Code, queued())
	}

	// An admin removes /srv/cache (queued); until the machine reports again its report still
	// lists it, but re-adding it is an addition all the same.
	// A later rescan without a list leaves it as the admin set it.
	if _, err := svc.db.Exec(`INSERT INTO fleet_commands (id, machine_id, type, payload, status, created_at) VALUES
		('c1','m1','rescan','{"exclude":[]}','pending',?), ('c2','m1','rescan','{}','pending',?)`,
		time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Add(time.Second).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, status, _ := svc.guardScanExcludes(as("operator"), "m1", json.RawMessage(`{"exclude":["/srv/cache"]}`)); status != http.StatusForbidden {
		t.Fatalf("an operator re-added a folder an admin had just removed: status %d", status)
	}
}

// The skip-folder check runs only for an otherwise valid request: an invalid folder is refused
// as invalid, without asking for a step-up first.
func TestScanExcludeGuardAfterValidation(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	rr := httptest.NewRecorder()
	body := `{"machine_id":"m1","type":"rescan","payload":{"exclude":["relative/path"]}}`
	svc.handleEnqueueCommand(rr, asOwner(httptest.NewRequest(http.MethodPost, "/api/fleet/command", strings.NewReader(body))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid folder: status %d (%s), want 400 before any step-up", rr.Code, rr.Body.String())
	}
}

// The skip-folder check doesn't wait for the machine to be online: a machine coming online between
// two checks must never let an unchecked rescan through.
func TestScanExcludeGuardedWhileOffline(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/fleet/command",
		strings.NewReader(`{"machine_id":"m1","type":"rescan","payload":{"exclude":["/opt"]}}`))
	r = r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: "operator", Username: "op1"}))
	svc.handleEnqueueCommand(rr, r)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("operator adding a folder on an offline machine: status %d, want 403", rr.Code)
	}
}
