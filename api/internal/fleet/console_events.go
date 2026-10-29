package fleet

import (
	"net/http"
	"sync"
	"time"

	"api/internal/auth"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"

	"github.com/gorilla/websocket"
)

// The console-events WebSocket replaces polling for the global console. A browser subscribes once;
// the panel pushes the caller's live session list across all accessible machines whenever a session
// opens or closes (hooked into the reconcile), and serves snapshot captures + kills over the same
// socket. All of it is owner-scoped — a subscriber only ever sees or touches its own sessions.

// consoleEventSub is one subscribed browser. The captured Principal carries the role + scope used to
// filter every push and request, so a subscriber can never be shown another user's sessions.
type consoleEventSub struct {
	conn    *websocket.Conn
	writeMu sync.Mutex

	mu sync.Mutex
	p  *router.Principal // refreshed every consoleRecheck, so a scope change applies
}

func (e *consoleEventSub) principal() *router.Principal {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.p
}

func (e *consoleEventSub) setPrincipal(p *router.Principal) {
	e.mu.Lock()
	e.p = p
	e.mu.Unlock()
}

func (e *consoleEventSub) send(v any) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	_ = e.conn.WriteJSON(v)
}

var (
	evMu   sync.Mutex
	evSubs = map[*consoleEventSub]struct{}{}
)

func evAdd(s *consoleEventSub)    { evMu.Lock(); evSubs[s] = struct{}{}; evMu.Unlock() }
func evRemove(s *consoleEventSub) { evMu.Lock(); delete(evSubs, s); evMu.Unlock() }

// consoleEventService is set in fleet.New; it lets the agentConn-side hooks (which hold no *Service)
// recompute a subscriber's scoped session list when something changes.
var consoleEventService *Service

// notifySessionsChanged pushes a fresh (owner-scoped) session list to every subscriber after a
// session opened or closed on machineID. Best-effort and asynchronous; reads the already-reconciled
// owner maps (no live-query), so it is cheap enough to call on every change.
func notifySessionsChanged(machineID string) {
	s := consoleEventService
	if s == nil || machineID == "" {
		return
	}
	evMu.Lock()
	if len(evSubs) == 0 {
		evMu.Unlock()
		return
	}
	subs := make([]*consoleEventSub, 0, len(evSubs))
	for sub := range evSubs {
		subs = append(subs, sub)
	}
	evMu.Unlock()
	for _, sub := range subs {
		go func(sub *consoleEventSub) {
			sub.send(map[string]any{"t": "sessions", "sessions": s.globalSessions(sub.principal(), false)})
		}(sub)
	}
}

// consoleEventsAccess checks what the console-events socket needs, at open and again every
// consoleRecheck while it stays open: a live, unlocked session with the operator role. It returns
// the principal, or the status and reason to refuse with.
func consoleEventsAccess(token string) (*router.Principal, int, string) {
	p, _, _ := router.Authenticate(token, false)
	if p == nil {
		return nil, http.StatusUnauthorized, "unauthorized"
	}
	if !auth.RoleAtLeast(p.Role, auth.RoleOperator) {
		return nil, http.StatusForbidden, "insufficient role"
	}
	return p, 0, ""
}

// HandleConsoleEvents is the browser-facing console-events WS. Mounted directly on the mux (bypassing
// REST RBAC), so it self-authenticates (session cookie/Bearer) and enforces the operator+ floor. Like
// an open console, it re-checks that every consoleRecheck: ending, locking or demoting the session
// closes it, and a scope change applies to what it lists and can act on.
func (s *Service) HandleConsoleEvents(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	p, code, reason := consoleEventsAccess(token)
	if p == nil {
		http.Error(w, reason, code)
		return
	}
	conn, err := browserUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(4096) // control frames only; no bulk data flows over this socket
	sub := &consoleEventSub{p: p, conn: conn}
	evAdd(sub)
	defer evRemove(sub)
	defer conn.Close()

	stopRecheck := make(chan struct{})
	defer close(stopRecheck)
	go recheckUntil(consoleRecheck, stopRecheck, func() string {
		p2, _, reason := consoleEventsAccess(token)
		if p2 == nil {
			return reason
		}
		if p2.UserID != p.UserID {
			return "session changed"
		}
		sub.setPrincipal(p2)
		return ""
	}, func(reason string) {
		sub.writeMu.Lock()
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "access ended: "+reason), time.Now().Add(time.Second))
		sub.writeMu.Unlock()
		conn.Close()
	})

	// Initial push: a fresh, live-queried list so the page paints real state immediately.
	sub.send(map[string]any{"t": "sessions", "sessions": s.globalSessions(p, true)})

	for {
		var f struct {
			T         string `json:"t"`
			MachineID string `json:"machine_id"`
			Session   string `json:"session"`
		}
		if err := conn.ReadJSON(&f); err != nil {
			return
		}
		switch f.T {
		case "snapshot":
			go s.wsSnapshot(sub, f.MachineID, f.Session)
		case "kill":
			go s.wsKill(sub, f.MachineID, f.Session)
		case "refresh":
			go func() { sub.send(map[string]any{"t": "sessions", "sessions": s.globalSessions(sub.principal(), true)}) }()
		}
	}
}

// scopedAgent resolves machineID to its live agent, enforcing scope + console-enabled + that the
// caller owns the given session. Returns the agent and the namespaced session, or ok=false.
func (s *Service) scopedAgent(p *router.Principal, machineID, clientSession string) (*agentConn, string, bool) {
	m, err := s.machineByID(machineID)
	if err != nil || m == nil || !scopeAllows(p, *m) || !m.ConsoleEnabled {
		return nil, "", false
	}
	a := regGet(machineID)
	if a == nil {
		return nil, "", false
	}
	eff := nsSession(p.UserID, clientSession)
	a.mu.Lock()
	owner := a.owners[eff]
	a.mu.Unlock()
	if owner != p.UserID {
		return nil, "", false
	}
	return a, eff, true
}

// wsSnapshot captures a session's current screen and pushes it back for a preview card.
func (s *Service) wsSnapshot(sub *consoleEventSub, machineID, clientSession string) {
	a, eff, ok := s.scopedAgent(sub.principal(), machineID, clientSession)
	if !ok {
		return
	}
	data, _ := a.requestSnapshot(eff, 2*time.Second)
	sub.send(map[string]any{"t": "snapshot-result", "machine_id": machineID, "session": clientSession, "data": data})
}

// wsKill destroys one of the caller's own sessions (the tab/card close button).
func (s *Service) wsKill(sub *consoleEventSub, machineID, clientSession string) {
	a, eff, ok := s.scopedAgent(sub.principal(), machineID, clientSession)
	if !ok {
		return
	}
	a.writeToAgent(consoleFrame{T: "kill", Session: eff})
	events.Audit("fleet", "console_kill", events.SeverityInfo, sub.principal().Username, "",
		"Console session killed (session "+eff+")")
	// session-exit from the agent will push the updated list; nudge now in case the agent is slow.
	notifySessionsChanged(machineID)
}
