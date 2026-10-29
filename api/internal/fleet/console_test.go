package fleet

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api/internal/bounded"
	"api/internal/helper"

	"github.com/gorilla/websocket"
)

func TestConsoleGrants(t *testing.T) {
	// Normal grant: single-use and bound to the minting user + machine (session not bound).
	id := mintGrant(7, "m1", "", false, time.Minute, 1)
	if _, ok := takeGrant(id, "m2", "s1", 7); ok {
		t.Error("grant must not validate for a different machine")
	}
	if _, ok := takeGrant(id, "m1", "s1", 8); ok {
		t.Error("a non-readonly grant must be bound to the minting user")
	}
	if _, ok := takeGrant(id, "m1", "s1", 7); !ok {
		t.Error("valid grant should be accepted for its user+machine")
	}
	if _, ok := takeGrant(id, "m1", "s1", 7); ok {
		t.Error("a single-use grant must not be reusable")
	}

	// Read-only (share) grant bound to one session: usable by another user, but only for that
	// session, and multiple uses.
	rid := mintGrant(7, "m1", "sX", true, time.Minute, 3)
	if _, ok := takeGrant(rid, "m1", "sOther", 99); ok {
		t.Error("a session-bound share grant must not open a different session")
	}
	if g, ok := takeGrant(rid, "m1", "sX", 99); !ok || !g.readonly {
		t.Error("readonly grant should be usable by another user for its own session and marked readonly")
	}
	if _, ok := takeGrant(rid, "m1", "sX", 100); !ok {
		t.Error("readonly grant should allow multiple uses")
	}

	// A refused take doesn't use the grant up.
	mid := mintGrant(7, "m1", "", false, time.Minute, 2)
	takeGrant(mid, "m2", "s1", 7)
	takeGrant(mid, "m1", "s1", 8)
	for i := 1; i <= 2; i++ {
		if _, ok := takeGrant(mid, "m1", "s1", 7); !ok {
			t.Errorf("use %d of 2 refused after wrong takes", i)
		}
	}
	if _, ok := takeGrant(mid, "m1", "s1", 7); ok {
		t.Error("a grant was used more times than minted")
	}

	// Expired grant is rejected.
	eid := mintGrant(7, "m1", "", false, -time.Second, 1)
	if _, ok := takeGrant(eid, "m1", "s1", 7); ok {
		t.Error("expired grant must be rejected")
	}
}

func newAgentConn() *agentConn {
	return &agentConn{
		bridges: map[string][]*consoleBridge{}, owners: map[string]int64{},
		opened: map[string]time.Time{}, seen: map[string]time.Time{},
		labels: map[string]int{}, snapWaiters: map[string][]*snapWaiter{},
	}
}

func TestOwnerFromSession(t *testing.T) {
	cases := map[string]int64{"7_sabc": 7, "42_x": 42, "nounderscore": 0, "_leading": 0, "x_y": 0}
	for in, want := range cases {
		if got := ownerFromSession(in); got != want {
			t.Errorf("ownerFromSession(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestLabelsStableAndGapped(t *testing.T) {
	a := newAgentConn()
	a.claimOwner("7_a", 7) // Session 1
	a.claimOwner("7_b", 7) // Session 2
	a.claimOwner("7_c", 7) // Session 3
	if a.labels["7_a"] != 1 || a.labels["7_b"] != 2 || a.labels["7_c"] != 3 {
		t.Fatalf("labels not assigned in order: %v", a.labels)
	}
	// Re-claiming keeps the same label (idempotent for the owner).
	a.claimOwner("7_b", 7)
	if a.labels["7_b"] != 2 {
		t.Errorf("re-claim must not renumber: got %d", a.labels["7_b"])
	}
	// Agent reports only a and c alive (b died while detached) → b is pruned, a/c keep their numbers
	// (gap at 2 preserved for any new session, matching the reference UI).
	a.syncSessions([]string{"7_a", "7_c"})
	if _, ok := a.owners["7_b"]; ok {
		t.Error("a session the agent no longer reports must be pruned")
	}
	if a.labels["7_a"] != 1 || a.labels["7_c"] != 3 {
		t.Errorf("surviving sessions must keep their labels: %v", a.labels)
	}
	a.claimOwner("7_d", 7) // next number continues upward, leaving the gap
	if a.labels["7_d"] != 4 {
		t.Errorf("next label should be 4 (gaps are kept), got %d", a.labels["7_d"])
	}
}

func TestCollectSessionsOwnerScoped(t *testing.T) {
	a := newAgentConn()
	a.claimOwner("7_a", 7)
	a.claimOwner("8_b", 8) // another operator's session
	got := collectSessions(a, 7, "m1", "web-01")
	if len(got) != 1 || got[0].ID != "a" || got[0].MachineName != "web-01" || got[0].Label != 1 {
		t.Fatalf("collectSessions must return only user 7's session, prefix-stripped, labelled: %+v", got)
	}
}

func TestSyncSessionsKeepsBridgedButUnreported(t *testing.T) {
	a := newAgentConn()
	a.claimOwner("7_fresh", 7)
	a.bridges["7_fresh"] = []*consoleBridge{{}} // a viewer is connected (just opened, not yet reported)
	a.syncSessions(nil)                         // agent reported nothing yet
	if _, ok := a.owners["7_fresh"]; !ok {
		t.Error("a session with a live viewer must not be pruned even if unreported")
	}
}

// A browser may only send its own-session frame types; the panel's control frames must never be
// relayable from a browser.
func TestBrowserFrameAllowlist(t *testing.T) {
	for _, ok := range []string{"data", "resize", "close", "file-put", "file-get", "file-list", "file-delete", "file-mkdir", "ping", "git", "docker", "diag"} {
		if !browserFrameTypes[ok] {
			t.Errorf("browser frame %q should be allowed", ok)
		}
	}
	for _, bad := range []string{"open", "sessions", "snapshot", "list-sessions", ""} {
		if browserFrameTypes[bad] {
			t.Errorf("browser frame %q must be dropped", bad)
		}
	}
}

// wsPair returns the two ends of one live WebSocket: the server side and the dialled client side.
func wsPair(t *testing.T) (server, client *websocket.Conn) {
	t.Helper()
	got := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		got <- c
	}))
	t.Cleanup(srv.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	server = <-got
	t.Cleanup(func() { client.Close(); server.Close() })
	return server, client
}

// A viewer joining a session someone else holds gets the current screen (tmux only redraws for
// the viewer whose join attached it), with the cursor where tmux has it; live output that the
// screen already shows isn't sent first (the screen would wipe it).
func TestShowScreenPaintsLaterViewer(t *testing.T) {
	a := newAgentConn()
	agentSide, agent := wsPair(t)
	a.conn = agentSide
	browserSide, browser := wsPair(t)
	a.addBridge("7_s1", &consoleBridge{browser: browserSide, session: "7_s1"})
	b := &consoleBridge{browser: browserSide, session: "7_s1"}
	if a.addBridge("7_s1", b) || !b.held {
		t.Fatal("a later viewer must wait for its screen")
	}
	go func() { // the agent answers the snapshot request, after some live output
		var f consoleFrame
		if agent.ReadJSON(&f) == nil && f.T == "snapshot" {
			b.write(consoleFrame{T: "data", Session: f.Session, Data: "bGl2ZQ=="})
			a.deliverSnapshot(consoleFrame{T: "snapshot-result", Session: f.Session, Cursor: "2 2",
				Data: base64.StdEncoding.EncodeToString([]byte("$ ls\nfile\n$ \n\n"))})
		}
	}()
	a.showScreen(b)

	var f consoleFrame
	browser.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := browser.ReadJSON(&f); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(f.Data)
	if want := "\x1b[0m\x1b[H\x1b[2J$ ls\r\nfile\r\n$ \x1b[3;3H"; f.T != "data" || f.Session != "7_s1" || string(raw) != want {
		t.Fatalf("got %s %s %q, want data 7_s1 %q", f.T, f.Session, raw, want)
	}
	if b.held {
		t.Fatal("still held after the screen was painted")
	}
}

// An agent that never answers a snapshot leaves no waiter behind, and the viewer gets live output.
func TestSnapshotTimeoutCleansUp(t *testing.T) {
	a := newAgentConn()
	agentSide, _ := wsPair(t)
	a.conn = agentSide
	browserSide, _ := wsPair(t)
	b := &consoleBridge{browser: browserSide, session: "7_s1", held: true}
	if _, ok := a.requestSnapshot("7_s1", 10*time.Millisecond); ok {
		t.Fatal("a reply nobody sent")
	}
	a.showScreen(b) // 2s timeout
	a.mu.Lock()
	n := len(a.snapWaiters)
	a.mu.Unlock()
	if n != 0 || b.held {
		t.Fatalf("%d waiters left, held=%v", n, b.held)
	}
}

// Past the cap a grant isn't minted ("") rather than another one dropped.
func TestGrantCap(t *testing.T) {
	saved := consoleGrants
	t.Cleanup(func() { consoleGrants = saved })
	consoleGrants = bounded.New[string, consoleGrant](1, bounded.Refuse)
	first := mintGrant(7, "m1", "", false, time.Minute, 1)
	if first == "" {
		t.Fatal("first grant not minted")
	}
	if id := mintGrant(7, "m1", "", false, time.Minute, 1); id != "" {
		t.Fatal("a grant was minted past the cap")
	}
	if _, ok := takeGrant(first, "m1", "s1", 7); !ok {
		t.Fatal("the existing grant was lost")
	}
}

// One user can't use up the grant room: past helper.MaxConsoleGrantsPerUser alive, their minting is refused while
// others still get grants. A grant-all list asks for each machine once, and no more than that many.
func TestGrantsPerUser(t *testing.T) {
	saved := consoleGrants
	t.Cleanup(func() { consoleGrants = saved })
	consoleGrants = bounded.New[string, consoleGrant](helper.MaxConsoleGrants, bounded.Refuse)
	for i := 0; i < helper.MaxConsoleGrantsPerUser; i++ {
		if mintGrant(7, "m1", "", false, time.Minute, 1) == "" {
			t.Fatalf("grant %d refused under the per-user cap", i+1)
		}
	}
	if mintGrant(7, "m1", "", false, time.Minute, 1) != "" {
		t.Fatal("a user got more grants than the per-user cap")
	}
	if mintGrant(8, "m1", "", false, time.Minute, 1) == "" {
		t.Fatal("another user was refused because of the first one")
	}

	ids := []string{"a", "b", "a", "a", "c", "b"}
	if got := grantAllTargets(ids); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("targets %v, want each machine once", got)
	}
	many := make([]string, 0, 3*helper.MaxConsoleGrantsPerUser)
	for i := 0; i < 3*helper.MaxConsoleGrantsPerUser; i++ {
		many = append(many, fmt.Sprint("machine-", i))
	}
	if n := len(grantAllTargets(many)); n != helper.MaxConsoleGrantsPerUser {
		t.Fatalf("%d targets from a long list, want %d", n, helper.MaxConsoleGrantsPerUser)
	}
}
