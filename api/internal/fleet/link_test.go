package fleet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The link rings the agent when a command is queued, keeps the machine online while up, and takes
// it offline once it has been down past the grace period; revoking takes it offline at once.
func TestLinkRingsAndTracksPresence(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc.HandleLink(w, withCert(r.WithContext(context.WithValue(r.Context(), machineCtxKey, &Machine{ID: "m1"})), time.Hour))
	}))
	defer srv.Close()

	if linkOnline("m1") {
		t.Fatal("a machine with no link must be offline")
	}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return linkOnline("m1") })

	if _, err := svc.Enqueue("m1", "rescan", nil); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var f map[string]string
	if err := conn.ReadJSON(&f); err != nil || f["t"] != "commands" {
		t.Fatalf("expected a ring, got %v (err %v)", f, err)
	}

	conn.Close()
	waitFor(t, func() bool {
		links.Lock()
		_, dropped := links.down["m1"]
		links.Unlock()
		return dropped
	})
	if !linkOnline("m1") {
		t.Fatal("within the grace period a dropped link still counts as online")
	}
	links.Lock()
	links.down["m1"] = time.Now().Add(-linkGrace)
	links.Unlock()
	if linkOnline("m1") {
		t.Fatal("past the grace period the machine is offline")
	}

	links.Lock()
	links.down["m1"] = time.Now()
	links.Unlock()
	linkTeardown("m1")
	if linkOnline("m1") {
		t.Fatal("teardown (revoke/delete) must take the machine offline at once")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// An agent that says it's going away (a reboot) is offline at once: no grace period.
func TestLinkGoingAwayIsOfflineAtOnce(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m2", false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc.HandleLink(w, withCert(r.WithContext(context.WithValue(r.Context(), machineCtxKey, &Machine{ID: "m2"})), time.Hour))
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return linkOnline("m2") })
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "reboot"), time.Now().Add(time.Second))
	waitFor(t, func() bool { return !linkOnline("m2") })
	conn.Close()
}
