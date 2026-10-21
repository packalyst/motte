package fleet

import (
	"testing"
	"time"
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
		labels: map[string]int{}, snapWaiters: map[string][]chan string{},
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
