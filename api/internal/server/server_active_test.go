package server

import (
	"testing"
	"time"
)

func TestWhoHost(t *testing.T) {
	cases := map[string]string{
		"laurs    pts/0        2026-08-18 12:19 (5.12.237.84)": "5.12.237.84",
		"root     pts/2        2026-08-18 09:00 (10.0.0.5)":    "10.0.0.5",
		"laurs    tty1         2026-08-18 08:00":               "", // local console, no host
		"laurs    pts/3        2026-08-18 08:00 (:0)":          "", // X display, not a remote
	}
	for line, want := range cases {
		if got := whoHost(line); got != want {
			t.Errorf("whoHost(%q) = %q, want %q", line, got, want)
		}
	}
}

// TestMarkActiveMembership: every ledger record whose (user, IP) has a live session is
// flagged active (membership, not "k most recent"); others are not.
func TestMarkActiveMembership(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	recent := []loginEvent{
		{User: "laurs", IP: "5.12.237.84", When: base.Add(-3 * time.Hour)},
		{User: "laurs", IP: "5.12.237.84", When: base},
		{User: "bob", IP: "9.9.9.9", When: base}, // no live session
	}
	markActiveMembership(recent, map[string]int{"laurs\x005.12.237.84": 2})
	if !recent[0].Active || !recent[1].Active {
		t.Error("all laurs@IP records should be flagged when a live session exists")
	}
	if recent[2].Active {
		t.Error("bob has no live session -> not active")
	}
}

// TestBuildActiveSessions: the shown time comes from loginctl's session Timestamp
// (authoritative), NOT the ledger — even when the ledger's newest record is stale.
func TestBuildActiveSessions(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	recent := []loginEvent{
		{User: "laurs", IP: "5.12.237.84", When: base.Add(-17 * 24 * time.Hour), Country: "RO"}, // stale ledger
	}
	live := liveSessions{
		counts: map[string]int{"laurs\x005.12.237.84": 3},
		newest: map[string]time.Time{"laurs\x005.12.237.84": base}, // loginctl: session started "now"
	}
	got := buildActiveSessions(recent, live)
	if len(got) != 1 {
		t.Fatalf("want 1 active row, got %d", len(got))
	}
	if got[0].Count != 3 || got[0].Country != "RO" {
		t.Errorf("unexpected row: %+v", got[0])
	}
	if !got[0].When.Equal(base) {
		t.Errorf("When must be loginctl's session time (%v), not the stale ledger, got %v", base, got[0].When)
	}
}

// TestBuildActiveSessionsFallbackTime: with no loginctl time (who fallback), fall back to
// the newest matching ledger record.
func TestBuildActiveSessionsFallbackTime(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	recent := []loginEvent{{User: "laurs", IP: "1.2.3.4", When: base}}
	live := liveSessions{counts: map[string]int{"laurs\x001.2.3.4": 1}, newest: map[string]time.Time{}}
	got := buildActiveSessions(recent, live)
	if len(got) != 1 || !got[0].When.Equal(base) {
		t.Errorf("fallback time should be the ledger's: %+v", got)
	}
}

func TestBuildActiveSessionsNone(t *testing.T) {
	empty := liveSessions{counts: map[string]int{}, newest: map[string]time.Time{}}
	if got := buildActiveSessions(nil, empty); len(got) != 0 {
		t.Errorf("no sessions => empty, got %d", len(got))
	}
}

// TestParseLoginctlTime: the exact loginctl format, in a known offset.
// TestIsPublicRemote: IPs classify by range; a non-IP hostname fails closed (remote)
// unless it's an obvious loopback name, so a UseDNS-logged public login is never dropped.
func TestIsPublicRemote(t *testing.T) {
	cases := map[string]bool{
		"":                      false,
		"127.0.0.1":             false,
		"::1":                   false,
		"10.0.0.5":              false,
		"192.168.1.10":          false,
		"169.254.1.1":           false,
		"5.12.237.84":           true,
		"[2001:db8::1]":         true,
		"localhost":             false, // loopback name
		"box.localhost":         false, // loopback name
		"attacker.example.com.": true,  // hostname -> fail closed
		"evil-host":             true,  // bare hostname -> fail closed
	}
	for in, want := range cases {
		if got := isPublicRemote(in); got != want {
			t.Errorf("isPublicRemote(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseLoginctlTime(t *testing.T) {
	loc := time.FixedZone("host", 3*3600) // +0300 (EEST)
	got := parseLoginctlTime("Sun 2026-09-06 15:10:50 EEST", loc)
	want := time.Date(2026, 9, 6, 15, 10, 50, 0, loc)
	if !got.Equal(want) {
		t.Errorf("parseLoginctlTime = %v, want %v", got, want)
	}
}
