package auth

import (
	"net/http"
	"time"

	"api/internal/bounded"
	"api/internal/helper"
)

// GraceWindow lets one login session skip the step-up prompt for a while after it confirmed: a
// successful step-up opens it, each use slides it by `slide`, never past `max` after the
// confirmation. It belongs to the session (keyed by its token's hash), not the user: a password or
// passkey given on one device doesn't cover another, or a stolen session cookie. It only waives
// re-entering the credentials; every other check of the request still runs, and an idle-locked
// session never gets this far (423 in the auth middleware first).
type GraceWindow struct {
	slide, max time.Duration
	at         *bounded.Map[string, grace]
}

type grace struct{ until, started time.Time }

// NewGraceWindow makes a window store holding at most capacity sessions; past that no new window
// opens (the credentials are asked again).
func NewGraceWindow(capacity int, slide, max time.Duration) *GraceWindow {
	return &GraceWindow{slide: slide, max: max, at: bounded.New[string, grace](capacity, bounded.Refuse)}
}

// FleetGrace is the fleet actions' shared window: one confirmation (a console open or a fleet
// command) covers that session's fleet actions for helper.ConsoleStepUpGrace, sliding, at most
// helper.ConsoleStepUpGraceMax. A console is already a root shell, so sharing the window with lesser
// fleet commands adds no authority.
var FleetGrace = NewGraceWindow(helper.MaxConsoleGraceWindows, helper.ConsoleStepUpGrace, helper.ConsoleStepUpGraceMax)

func graceKey(r *http.Request) string {
	if tok := helper.SessionToken(r); tok != "" {
		return hashToken(tok)
	}
	return ""
}

// use reports whether r's session is inside its window, and slides it (never past the cap).
func (g *GraceWindow) use(r *http.Request) bool {
	key := graceKey(r)
	if key == "" {
		return false
	}
	now := time.Now()
	inside := false
	g.at.Update(key, now, func(w *grace, found bool) time.Time {
		if !found {
			return now // no window: nothing to keep
		}
		inside = true
		w.until = now.Add(g.slide)
		if limit := w.started.Add(g.max); w.until.After(limit) {
			w.until = limit
		}
		return w.until
	})
	return inside
}

// open starts r's session window after a successful step-up.
func (g *GraceWindow) open(r *http.Request) {
	key := graceKey(r)
	if key == "" {
		return
	}
	now := time.Now()
	g.at.Update(key, now, func(w *grace, _ bool) time.Time {
		*w = grace{until: now.Add(g.slide), started: now}
		return w.until
	})
}
