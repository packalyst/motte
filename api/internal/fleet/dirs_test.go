package fleet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	if _, status, err := svc.enqueueGuarded(as("owner"), "m1", "set-tool", "", "", json.RawMessage(`{"tool":"crowdsec","enabled":false}`)); err == nil || status != http.StatusPreconditionRequired {
		t.Fatalf("no step-up: status %d err %v", status, err)
	}
	for _, p := range []string{`{"tool":"nmap","enabled":true}`, `{"tool":"crowdsec"}`, `{}`} {
		if validateCommandPayload("set-tool", json.RawMessage(p)) == nil {
			t.Errorf("accepted %s", p)
		}
	}
}
