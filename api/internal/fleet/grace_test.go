package fleet

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func requestWithSession(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/fleet/command", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// TestFleetGracePerSessionAndCapped: the password-free window belongs to the login session that
// typed the password (not the user's other sessions), slides with use, and ends at the cap however
// busy the session is.
func TestFleetGracePerSessionAndCapped(t *testing.T) {
	a, b := requestWithSession("synthetic-session-a"), requestWithSession("synthetic-session-b")
	if useFleetGrace(a) {
		t.Fatal("no window before a password was typed")
	}
	openFleetGrace(a)
	if !useFleetGrace(a) {
		t.Fatal("the session that typed the password should be inside its window")
	}
	if useFleetGrace(b) {
		t.Fatal("another session of the same user must not share the window")
	}
	if useFleetGrace(httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Fatal("a request without a session has no window")
	}

	// Typed long ago and used all along: still capped.
	key := graceKey(a)
	setWindow := func(until, started time.Time) {
		stepUpGraceAt.Update(key, time.Now(), func(g *fleetGrace, _ bool) time.Time {
			*g = fleetGrace{until: until, started: started}
			return until
		})
	}
	setWindow(time.Now().Add(time.Minute), time.Now().Add(-fleetStepUpGraceMax+time.Second))
	if !useFleetGrace(a) {
		t.Fatal("still inside the cap")
	}
	if g, _ := stepUpGraceAt.Get(key, time.Now()); time.Until(g.until) > 2*time.Second {
		t.Fatalf("the window slid past the cap: %v left", time.Until(g.until))
	}
	setWindow(time.Now().Add(-time.Second), time.Now().Add(-2*time.Hour))
	if useFleetGrace(a) {
		t.Fatal("past the cap the password is asked again")
	}
}
