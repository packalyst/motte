package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api/internal/helper"
)

func graceRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/fleet/command", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// TestGracePerSessionAndCapped: the password-free window belongs to the login session that
// typed the password (not the user's other sessions), slides with use, and ends at the cap however
// busy the session is.
func TestGracePerSessionAndCapped(t *testing.T) {
	g := NewGraceWindow(10, helper.ConsoleStepUpGrace, helper.ConsoleStepUpGraceMax)
	a, b := graceRequest("synthetic-session-a"), graceRequest("synthetic-session-b")
	if g.use(a) {
		t.Fatal("no window before a password was typed")
	}
	g.open(a)
	if !g.use(a) {
		t.Fatal("the session that typed the password should be inside its window")
	}
	if g.use(b) {
		t.Fatal("another session of the same user must not share the window")
	}
	if g.use(httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Fatal("a request without a session has no window")
	}

	// Typed long ago and used all along: still capped.
	key := graceKey(a)
	setWindow := func(until, started time.Time) {
		g.at.Update(key, time.Now(), func(g *grace, _ bool) time.Time {
			*g = grace{until: until, started: started}
			return until
		})
	}
	setWindow(time.Now().Add(time.Minute), time.Now().Add(-helper.ConsoleStepUpGraceMax+time.Second))
	if !g.use(a) {
		t.Fatal("still inside the cap")
	}
	if g, _ := g.at.Get(key, time.Now()); time.Until(g.until) > 2*time.Second {
		t.Fatalf("the window slid past the cap: %v left", time.Until(g.until))
	}
	setWindow(time.Now().Add(-time.Second), time.Now().Add(-2*time.Hour))
	if g.use(a) {
		t.Fatal("past the cap the password is asked again")
	}
}
