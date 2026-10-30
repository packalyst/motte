package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api/internal/helper"

	"github.com/gorilla/websocket"
)

// withCert gives a test request the client certificate requireClientCert would have checked,
// valid for ttl from now.
func withCert(r *http.Request, ttl time.Duration) *http.Request {
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: time.Now().Add(ttl)}}}
	return r
}

// An agent's link is closed by the panel when the certificate it was opened with expires (an
// expired certificate is never accepted, not even on a socket opened before); one with no
// certificate is closed at once.
func TestAgentSocketClosedAtCertExpiry(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", false)
	for _, c := range []struct {
		name string
		cert func(*http.Request) *http.Request
	}{
		{"expiring certificate", func(r *http.Request) *http.Request { return withCert(r, 300*time.Millisecond) }},
		{"no certificate", func(r *http.Request) *http.Request { return r }},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			svc.HandleLink(w, c.cert(r.WithContext(context.WithValue(r.Context(), machineCtxKey, &Machine{ID: "m1"}))))
		}))
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _, err = conn.ReadMessage()
		if err == nil || time.Since(start) > 3*time.Second {
			t.Fatalf("%s: socket still open after %v (err %v)", c.name, time.Since(start), err)
		}
		conn.Close()
		srv.Close()
	}
}

// The console channel is refused while the machine's console is off.
func TestConsoleChannelNeedsConsoleOn(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", false)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/console", nil)
	svc.HandleConsoleChannel(rr, withCert(r.WithContext(context.WithValue(r.Context(), machineCtxKey, &Machine{ID: "m1"})), time.Hour))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("console off: %d, want 403", rr.Code)
	}
}

// What the agent sends can't grow the console maps: output for sessions the panel doesn't track
// adds nothing, and a session list adopts no more than a machine may have.
func TestConsoleMapsBoundedByAgent(t *testing.T) {
	a := &agentConn{
		machineID: "m1", bridges: map[string][]*consoleBridge{}, owners: map[string]int64{},
		opened: map[string]time.Time{}, seen: map[string]time.Time{}, labels: map[string]int{},
		snapWaiters: map[string][]*snapWaiter{}, recs: map[string]*consoleRecorder{},
	}
	for i := 0; i < 10_000; i++ {
		a.touch(fmt.Sprintf("7_flood%d", i))
		a.routeToBrowsers(consoleFrame{T: "data", Session: fmt.Sprintf("7_flood%d", i)})
	}
	if len(a.opened) != 0 || len(a.seen) != 0 || len(a.bridges) != 0 || len(a.labels) != 0 {
		t.Fatalf("unknown sessions grew the maps: opened %d seen %d bridges %d labels %d", len(a.opened), len(a.seen), len(a.bridges), len(a.labels))
	}

	ids := make([]string, 100_000)
	for i := range ids {
		ids[i] = fmt.Sprintf("7_s%d", i)
	}
	a.syncSessions(ids)
	max := helper.MaxConsoleSessionsPerMachine
	if len(a.owners) != max || len(a.opened) != max || len(a.seen) != max || len(a.labels) != max {
		t.Fatalf("adopted owners %d opened %d seen %d labels %d, want %d each", len(a.owners), len(a.opened), len(a.seen), len(a.labels), max)
	}
	// A tracked session still counts its activity.
	before := a.seen["7_s0"]
	time.Sleep(time.Millisecond)
	a.touch("7_s0")
	if !a.seen["7_s0"].After(before) {
		t.Fatal("a tracked session's activity was not recorded")
	}
}
