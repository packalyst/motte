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
	p       *router.Principal
	conn    *websocket.Conn
	writeMu sync.Mutex
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
			sub.send(map[string]any{"t": "sessions", "sessions": s.globalSessions(sub.p, false)})
		}(sub)
	}
}

// HandleConsoleEvents is the browser-facing console-events WS. Mounted directly on the mux (bypassing
// REST RBAC), so it self-authenticates (session cookie/Bearer) and enforces the operator+ floor.
func (s *Service) HandleConsoleEvents(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	p, ok := router.ResolvePrincipal(token)
	if !ok || p == nil || p.Locked {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !auth.RoleAtLeast(p.Role, auth.RoleOperator) {
		http.Error(w, "insufficient role", http.StatusForbidden)
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
			go func() { sub.send(map[string]any{"t": "sessions", "sessions": s.globalSessions(p, true)}) }()
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
	a, eff, ok := s.scopedAgent(sub.p, machineID, clientSession)
	if !ok {
		return
	}
	data, _ := a.requestSnapshot(eff, 2*time.Second)
	sub.send(map[string]any{"t": "snapshot-result", "machine_id": machineID, "session": clientSession, "data": data})
}

// wsKill destroys one of the caller's own sessions (the tab/card close button).
func (s *Service) wsKill(sub *consoleEventSub, machineID, clientSession string) {
	a, eff, ok := s.scopedAgent(sub.p, machineID, clientSession)
	if !ok {
		return
	}
	a.writeToAgent(consoleFrame{T: "kill", Session: eff})
	events.Audit("fleet", "console_kill", events.SeverityInfo, sub.p.Username, "",
		"Console session killed (session "+eff+")")
	// session-exit from the agent will push the updated list; nudge now in case the agent is slow.
	notifySessionsChanged(machineID)
}
