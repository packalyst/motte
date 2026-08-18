package server

import (
	"testing"
	"time"
)

func TestWhoHost(t *testing.T) {
	cases := map[string]string{
		"alice    pts/0        2026-08-18 12:19 (198.51.100.7)": "198.51.100.7",
		"root     pts/2        2026-08-18 09:00 (10.0.0.5)":     "10.0.0.5",
		"alice    tty1         2026-08-18 08:00":                "",   // local console, no host
		"alice    pts/3        2026-08-18 08:00 (:0)":           "",   // X display, not a remote
	}
	for line, want := range cases {
		if got := whoHost(line); got != want {
			t.Errorf("whoHost(%q) = %q, want %q", line, got, want)
		}
	}
}

// TestMarkActiveLogins: 4 historical logins from the same user+IP, but only 2 live
// sessions -> the 2 MOST RECENT are flagged active, the 2 older stay history.
func TestMarkActiveLogins(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	recent := []loginEvent{
		{User: "alice", IP: "198.51.100.7", When: base.Add(-3 * time.Hour)}, // oldest
		{User: "alice", IP: "198.51.100.7", When: base.Add(-2 * time.Hour)},
		{User: "alice", IP: "198.51.100.7", When: base.Add(-1 * time.Hour)},
		{User: "alice", IP: "198.51.100.7", When: base}, // newest
		{User: "bob", IP: "9.9.9.9", When: base},       // different pair, no live session
	}
	counts := map[string]int{"alice\x00198.51.100.7": 2}
	markActiveLogins(recent, counts)

	activeAt := func(i int) bool { return recent[i].Active }
	if activeAt(0) || activeAt(1) {
		t.Error("older logins should NOT be active")
	}
	if !activeAt(2) || !activeAt(3) {
		t.Error("the 2 most-recent matching logins should be active")
	}
	if activeAt(4) {
		t.Error("a login with no matching live session must not be flagged active")
	}
}

func TestMarkActiveLoginsNoSessions(t *testing.T) {
	recent := []loginEvent{{User: "alice", IP: "1.2.3.4", When: time.Now()}}
	markActiveLogins(recent, map[string]int{}) // who returned nothing
	if recent[0].Active {
		t.Error("no live sessions => nothing active")
	}
}
