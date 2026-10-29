package fleet

// Browser console — the panel side (roadmap point 7). Two WebSocket hops bridged in-process:
//
//	browser ──(main API, cookie auth + RBAC + scope + step-up grant)──► panel ◄──(fleet mTLS
//	                                                                              listener)── agent
//
// The agent dials a persistent console channel (HandleConsoleChannel, client-cert authed) that
// multiplexes many sessions by id. A browser opens a console WS (HandleBrowserConsole) carrying a
// short-lived step-up grant; the panel registers it as a viewer of a session and relays frames to the
// machine's agent channel. Read-only viewers receive output but their input is dropped. Output can
// be tee'd to an asciinema recording when the host has it enabled. Every open/close is audited.
//
// This is a full interactive shell — deliberately separate from the strict command allowlist — so
// it is gated hard: per-host enable (DB + agent flag), RBAC+scope, step-up, audit, recording.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/auth"
	"api/internal/bounded"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"

	"github.com/gorilla/websocket"
)

// consoleStepUp re-authenticates the operator from body-supplied creds (mirrors the fleet command
// guardrail; we cannot use router.StepUp here because it re-reads the request body we already
// decoded). Returns (0, nil) on success, else a 428 status + message.
func (s *Service) consoleStepUp(r *http.Request, currentPassword, currentTOTP string) (int, error) {
	_, userID := s.actingAdmin(r)
	authSvc := auth.GetService()
	if authSvc == nil || userID == 0 || currentPassword == "" {
		return http.StatusPreconditionRequired, fmt.Errorf("step-up re-authentication required")
	}
	if err := authSvc.VerifyStepUp(userID, currentPassword, currentTOTP); err != nil {
		if errors.Is(err, auth.ErrStepUpTOTPRequired) {
			return http.StatusPreconditionRequired, fmt.Errorf("two-factor authentication code required")
		}
		return http.StatusPreconditionRequired, fmt.Errorf("step-up re-authentication failed")
	}
	return 0, nil
}

// helper.ConsoleStepUpGrace is how long a single successful fleet re-auth is honoured without prompting
// again. One operator action that re-authenticates — opening a console OR running a confirm-tier
// fleet command — opens the window; while it is open the same LOGIN SESSION isn't re-prompted for
// either. The window belongs to that session, not the user: a password typed on one device doesn't
// cover another, or a stolen session cookie. It slides on every pass, so continuous administration
// isn't interrupted, but never past helper.ConsoleStepUpGraceMax after the password was typed. It only waives
// the password RE-ENTRY: the operator role, machine scope and per-host enable flag are still checked
// on every request, and an idle-locked session never reaches here (the request 423s in auth
// middleware first), so grace can't bypass the lock. A console is already a root shell, so sharing
// the window with lesser fleet commands adds no authority. Not used by the enable toggle, which is
// rarer/higher-impact and always re-authenticates.

type fleetGrace struct{ until, started time.Time }

// stepUpGraceAt holds each login session's window (token hash → window), one per session that
// typed its password; past helper.MaxConsoleGraceWindows new windows aren't opened (the password is
// asked again).
var stepUpGraceAt = bounded.New[string, fleetGrace](helper.MaxConsoleGraceWindows, bounded.Refuse)

// graceKey identifies the caller's login session without keeping its token.
func graceKey(r *http.Request) string {
	tok := helper.SessionToken(r)
	if tok == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// useFleetGrace reports whether the caller's session is inside its window, and slides it (never
// past the cap).
func useFleetGrace(r *http.Request) bool {
	key := graceKey(r)
	if key == "" {
		return false
	}
	now := time.Now()
	inside := false
	stepUpGraceAt.Update(key, now, func(g *fleetGrace, found bool) time.Time {
		if !found {
			return now // no window: nothing to keep
		}
		inside = true
		g.until = now.Add(helper.ConsoleStepUpGrace)
		if limit := g.started.Add(helper.ConsoleStepUpGraceMax); g.until.After(limit) {
			g.until = limit
		}
		return g.until
	})
	return inside
}

// openFleetGrace starts the caller's window after they typed their password.
func openFleetGrace(r *http.Request) {
	key := graceKey(r)
	if key == "" {
		return
	}
	now := time.Now()
	stepUpGraceAt.Update(key, now, func(g *fleetGrace, _ bool) time.Time {
		*g = fleetGrace{until: now.Add(helper.ConsoleStepUpGrace), started: now}
		return g.until
	})
}

// consoleStepUpGraced is consoleStepUp with the shared fleet grace window: within the window it
// passes WITHOUT a password (and slides the window); otherwise it re-authenticates as usual and, on
// success, opens the window. Used by the open-console grant endpoints.
func (s *Service) consoleStepUpGraced(r *http.Request, currentPassword, currentTOTP string) (int, error) {
	_, userID := s.actingAdmin(r)
	if userID == 0 {
		return http.StatusPreconditionRequired, fmt.Errorf("step-up re-authentication required")
	}
	if useFleetGrace(r) {
		return 0, nil
	}
	if status, err := s.consoleStepUp(r, currentPassword, currentTOTP); err != nil {
		return status, err
	}
	openFleetGrace(r)
	return 0, nil
}

// consoleFrame mirrors the agent's wire protocol (JSON; binary is base64 in Data).
type consoleFrame struct {
	T       string `json:"t"`
	Session string `json:"session"`
	Cols    uint16 `json:"cols,omitempty"`
	Rows    uint16 `json:"rows,omitempty"`
	Data    string `json:"data,omitempty"`
	Path    string `json:"path,omitempty"`
	EOF     bool   `json:"eof,omitempty"`
	Start   bool   `json:"start,omitempty"` // file-put: an upload's first chunk (relayed to the agent)
	Msg     string `json:"msg,omitempty"`
	// Relayed verbatim (file-list-result directory entries). The panel is a pure relay for this —
	// it never inspects the contents, so RawMessage round-trips whatever the agent produced.
	Items json.RawMessage `json:"items,omitempty"`
	// sessions-list (agent → panel on connect): the live panel-* tmux session ids, used to rebuild
	// the owner map so resume survives a panel restart.
	Sessions []string `json:"sessions,omitempty"`
	// ping/pong (browser ↔ agent, relayed verbatim): Ts echoes the browser clock for a latency
	// measurement; Cwd carries the session's current working directory for the status bar.
	Ts  int64  `json:"ts,omitempty"`
	Cwd string `json:"cwd,omitempty"`
	// git / docker tool panels (relayed verbatim): Action selects the operation (docker ps/logs/
	// start/stop/restart); Path carries the container id/name for a per-container action.
	Action string `json:"action,omitempty"`
	// snapshot-result: the cursor position as "row col" (0-based), from agents that send it.
	Cursor string `json:"cursor,omitempty"`
}

var (
	agentUpgrader   = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }} // mTLS authenticates
	browserUpgrader = websocket.Upgrader{CheckOrigin: helper.SameOrigin}
)

// ---- agent channel registry ---------------------------------------------------------------------

type consoleBridge struct {
	browser  *websocket.Conn
	writeMu  sync.Mutex
	session  string
	readonly bool
	// held (guarded by writeMu): a viewer joining a held session gets no live output until its first
	// screen is painted (showScreen) — that screen already shows it, and would wipe it.
	held bool
}

func (b *consoleBridge) write(f consoleFrame) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if b.held && f.T == "data" {
		return
	}
	b.sendLocked(f)
}

// browserWriteWait bounds one write to a viewer. Writes run on the agent channel's read loop, so a
// viewer that stopped reading (a phone gone to sleep) must not hold it up: the channel would miss
// its keepalive and drop every session's viewers on the machine.
const browserWriteWait = 5 * time.Second

// sendLocked writes f to the viewer, and drops a viewer that doesn't take it in time (its socket
// closes, which ends its handler and detaches it; it can reconnect). Caller holds writeMu.
func (b *consoleBridge) sendLocked(f consoleFrame) {
	_ = b.browser.SetWriteDeadline(time.Now().Add(browserWriteWait))
	if err := b.browser.WriteJSON(f); err != nil {
		b.browser.Close()
	}
}

type agentConn struct {
	conn      *websocket.Conn
	machineID string // which machine this channel belongs to (for push notifications)
	writeMu   sync.Mutex
	mu        sync.Mutex
	bridges   map[string][]*consoleBridge // session id → viewers
	owners    map[string]int64            // session id → user who opened it (interactive attach is owner-only)
	opened    map[string]time.Time        // session id → first open (max-duration reaper)
	seen      map[string]time.Time        // session id → last activity (idle reaper)
	labels    map[string]int              // session id → friendly per-machine number ("Session N")
	nextNum   int                         // next label number to hand out for this machine

	sessWaiters []chan struct{}          // woken when the next sessions-list arrives (live-query)
	snapWaiters map[string][]*snapWaiter // session id → waiters for a snapshot-result

	recs map[string]*consoleRecorder // session id → its open recording (guarded by mu)
}

// ensureLabel assigns a stable, per-machine "Session N" number to a session the first time it is
// seen. Numbers only go up (closed sessions leave gaps, matching the reference UI); they may
// renumber after a panel restart, which is fine — the label is cosmetic. Caller holds a.mu.
func (a *agentConn) ensureLabel(session string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	if _, ok := a.labels[session]; !ok {
		a.nextNum++
		a.labels[session] = a.nextNum
	}
}

// A resumable shell lives on until it exits — so cap how long one can stay open (max-duration) or
// sit idle (idle timeout). The reaper tells the agent to KILL (not detach) past-limit sessions.

// touch records activity on a session (first open sets `opened`; every call refreshes `seen`), so
// the reaper can tell an active long-running command from an abandoned shell.
func (a *agentConn) touch(session string) {
	a.mu.Lock()
	now := time.Now()
	if _, ok := a.opened[session]; !ok {
		a.opened[session] = now
	}
	a.seen[session] = now
	a.mu.Unlock()
}

// syncSessions rebuilds the owner map from the agent's authoritative list of live tmux sessions
// (their names embed the owner: "<userID>_<client id>"). This restores resume after a panel restart
// or agent reconnect, when the in-memory owners map was lost but the tmux sessions survived. It only
// ADDS missing entries — it never overrides a session the panel is already tracking.
func (a *agentConn) syncSessions(ids []string) {
	now := time.Now()
	live := make(map[string]bool, len(ids))
	changed := false
	a.mu.Lock()
	for _, id := range ids {
		uid := ownerFromSession(id)
		if uid == 0 {
			continue
		}
		live[id] = true
		if _, ok := a.owners[id]; !ok {
			a.owners[id] = uid
			changed = true
		}
		if _, ok := a.opened[id]; !ok {
			a.opened[id] = now // real open time is unknown after a restart; start the reaper clock now
		}
		if _, ok := a.seen[id]; !ok {
			a.seen[id] = now
		}
		a.ensureLabel(id)
	}
	// Prune ghosts: an owner the agent did NOT report is a session that has died on the host. Skip
	// any that still has a live viewer — a session opened just after the report was taken hasn't been
	// reported yet but is clearly alive (its bridge is connected), so we must not drop it.
	for id := range a.owners {
		if !live[id] && len(a.bridges[id]) == 0 {
			delete(a.owners, id)
			delete(a.opened, id)
			delete(a.seen, id)
			delete(a.labels, id)
			changed = true
		}
	}
	// Wake anyone blocked in requestSessions — a fresh, reconciled list is now in place.
	for _, ch := range a.sessWaiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	a.sessWaiters = nil
	a.mu.Unlock()
	if changed {
		notifySessionsChanged(a.machineID) // push the new list to console-events subscribers
	}
}

// requestSessions live-queries the agent: it asks for a fresh session list and blocks (up to
// timeout) until the reply lands and reconciles the owner map, so the caller then reads an
// up-to-the-moment list instead of a possibly-stale cache. Falls through on timeout (agent slow /
// old agent that doesn't answer) — the caller still gets the last known map.
func (a *agentConn) requestSessions(timeout time.Duration) {
	ch := make(chan struct{}, 1)
	a.mu.Lock()
	a.sessWaiters = append(a.sessWaiters, ch)
	a.mu.Unlock()
	a.writeToAgent(consoleFrame{T: "list-sessions"})
	select {
	case <-ch:
	case <-time.After(timeout):
	}
}

// snapWaiter is one wait for a snapshot-result: fn gets the agent's reply, then done is closed.
type snapWaiter struct {
	fn   func(consoleFrame)
	done chan struct{}
}

// awaitSnapshot asks the agent for a one-shot capture of a session's current screen and waits up to
// timeout for fn to have run with the reply. fn runs on the agent's read loop, so before any frame
// the agent sent after the reply; it can still run (late) after a timeout. Owner-scoped by the caller.
func (a *agentConn) awaitSnapshot(session string, timeout time.Duration, fn func(consoleFrame)) bool {
	w := &snapWaiter{fn: fn, done: make(chan struct{})}
	a.mu.Lock()
	a.snapWaiters[session] = append(a.snapWaiters[session], w)
	a.mu.Unlock()
	a.writeToAgent(consoleFrame{T: "snapshot", Session: session})
	select {
	case <-w.done:
		return true
	case <-time.After(timeout):
	}
	a.mu.Lock() // no reply (an agent that never answers must not pile up waiters)
	ws := a.snapWaiters[session]
	for i, x := range ws {
		if x == w {
			a.snapWaiters[session] = append(ws[:i], ws[i+1:]...)
			break
		}
	}
	if len(a.snapWaiters[session]) == 0 {
		delete(a.snapWaiters, session)
	}
	a.mu.Unlock()
	return false
}

// requestSnapshot returns a session's current screen as base64 text (for the preview cards), and
// whether it arrived within timeout.
func (a *agentConn) requestSnapshot(session string, timeout time.Duration) (string, bool) {
	ch := make(chan string, 1)
	if !a.awaitSnapshot(session, timeout, func(f consoleFrame) { ch <- f.Data }) {
		return "", false
	}
	return <-ch, true
}

// showScreen paints a session's current screen on one viewer that joined a session another viewer
// already holds (addBridge marked it held). tmux redraws only for the viewer whose join attached it
// (the first), so a later one (a second browser, or a reconnect before the old socket is noticed
// dead) would otherwise start on a blank terminal and see only output from then on. Live output
// reaches it once the screen is painted, or after the timeout without one.
func (a *agentConn) showScreen(b *consoleBridge) {
	release := func(screen []byte) {
		b.writeMu.Lock()
		defer b.writeMu.Unlock()
		if !b.held {
			return
		}
		b.held = false
		if len(screen) > 0 {
			b.sendLocked(consoleFrame{T: "data", Session: b.session, Data: base64.StdEncoding.EncodeToString(screen)})
		}
	}
	if !a.awaitSnapshot(b.session, 2*time.Second, func(f consoleFrame) { release(screenPaint(f)) }) {
		release(nil)
	}
}

// screenPaint turns a snapshot-result into terminal output that replaces the screen with it: home
// and clear, then the captured lines, then the cursor where tmux has it. nil when there's nothing.
func screenPaint(f consoleFrame) []byte {
	raw, err := base64.StdEncoding.DecodeString(f.Data)
	if err != nil || len(raw) == 0 {
		return nil
	}
	// capture-pane prints lines ending in "\n"; the terminal needs "\r\n".
	screen := "\x1b[0m\x1b[H\x1b[2J" + strings.ReplaceAll(strings.TrimRight(string(raw), "\n"), "\n", "\r\n")
	var row, col int
	if n, _ := fmt.Sscanf(f.Cursor, "%d %d", &row, &col); n == 2 && row >= 0 && col >= 0 && row < 1000 && col < 1000 {
		screen += fmt.Sprintf("\x1b[%d;%dH", row+1, col+1)
	}
	return []byte(screen)
}

// deliverSnapshot hands a snapshot-result to everyone waiting on that session.
func (a *agentConn) deliverSnapshot(f consoleFrame) {
	a.mu.Lock()
	waiters := a.snapWaiters[f.Session]
	delete(a.snapWaiters, f.Session)
	a.mu.Unlock()
	for _, w := range waiters {
		w.fn(f)
		close(w.done)
	}
}

// ownerFromSession extracts the user id a namespaced session belongs to ("<userID>_..." → userID).
// Returns 0 (ignored) if the id isn't in that form.
func ownerFromSession(id string) int64 {
	i := strings.IndexByte(id, '_')
	if i <= 0 {
		return 0
	}
	uid, err := strconv.ParseInt(id[:i], 10, 64)
	if err != nil {
		return 0
	}
	return uid
}

// reapExpired kills sessions past the idle or max-duration limit. It only signals the agent
// (writeToAgent "kill"); the agent destroys the tmux session and replies session-exit, which the
// normal routeToBrowsers path uses to free owner/bridges — so ownership is never dropped while a
// shell is still alive (no cross-operator hijack), and an un-upgraded agent simply ignores "kill".
func (a *agentConn) reapExpired() {
	now := time.Now()
	a.mu.Lock()
	var kill []string
	for id := range a.owners {
		op, sn := a.opened[id], a.seen[id]
		if (!op.IsZero() && now.Sub(op) > helper.ConsoleMaxDuration) || (!sn.IsZero() && now.Sub(sn) > helper.ConsoleIdleTimeout) {
			kill = append(kill, id)
		}
	}
	a.mu.Unlock()
	for _, id := range kill {
		a.writeToAgent(consoleFrame{T: "kill", Session: id})
	}
}

// claimOwner records the opener of a session. It returns false if the session already has a
// DIFFERENT owner — ownership persists across a detach (the tmux session lives on for resume), so a
// second operator can't reattach a shell the first opened. Idempotent for the same user.
// claimOwner makes userID the owner of a session, or confirms they already are (a reattach). A new
// session counts against helper.MaxConsoleSessionsPerUser (the user's shells on this machine) and
// helper.MaxConsoleSessionsPerMachine (everyone's): each is a real shell on the host, so neither a
// user nor a stolen session can start them without end. Returns "" when allowed, else why not.
func (a *agentConn) claimOwner(session string, userID int64) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ex, ok := a.owners[session]; ok {
		if ex != userID {
			return "session belongs to another operator"
		}
		return ""
	}
	mine := 0
	for _, owner := range a.owners {
		if owner == userID {
			mine++
		}
	}
	switch {
	case mine >= helper.MaxConsoleSessionsPerUser:
		return fmt.Sprintf("you have %d sessions open on this machine; close one first", mine)
	case len(a.owners) >= helper.MaxConsoleSessionsPerMachine:
		return fmt.Sprintf("this machine has %d sessions open; close one first", len(a.owners))
	}
	a.owners[session] = userID
	a.ensureLabel(session)
	return ""
}

// isOwner reports whether userID currently owns the session (used to gate minting a share link).
func (a *agentConn) isOwner(session string, userID int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.owners[session] == userID
}

func (a *agentConn) writeToAgent(f consoleFrame) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_ = a.conn.WriteJSON(f)
}

// addBridge attaches a browser to a session, unless helper.MaxConsoleViewers are already attached
// (ok false). first reports whether it is the only one.
func (a *agentConn) addBridge(session string, b *consoleBridge) (first, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.bridges[session]) >= helper.MaxConsoleViewers {
		return false, false
	}
	first = len(a.bridges[session]) == 0
	b.held = !first // not shared yet: showScreen releases it
	a.bridges[session] = append(a.bridges[session], b)
	return first, true
}

func (a *agentConn) removeBridge(session string, b *consoleBridge) (last bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	list := a.bridges[session]
	for i, x := range list {
		if x == b {
			a.bridges[session] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(a.bridges[session]) == 0 {
		delete(a.bridges, session)
		return true
	}
	return false
}

// routeToBrowsers forwards one agent frame to every viewer of its session (teeing output + command
// markers into the session's recording, once per frame), and tears the session down on session-exit.
func (a *agentConn) routeToBrowsers(f consoleFrame) {
	a.recordFrame(f)
	a.mu.Lock()
	viewers := append([]*consoleBridge(nil), a.bridges[f.Session]...)
	a.mu.Unlock()
	for _, b := range viewers {
		b.write(f)
	}
	if f.T == "session-exit" {
		a.closeRecorder(f.Session) // the shell ended — finalize its recording
		a.mu.Lock()
		delete(a.bridges, f.Session)
		delete(a.owners, f.Session) // the shell ended — free the session id
		delete(a.opened, f.Session)
		delete(a.seen, f.Session)
		delete(a.labels, f.Session)
		a.mu.Unlock()
		notifySessionsChanged(a.machineID) // a session ended — refresh subscribers
	}
}

func (a *agentConn) closeAll() {
	a.mu.Lock()
	all := a.bridges
	a.bridges = map[string][]*consoleBridge{}
	recs := a.recs
	a.recs = map[string]*consoleRecorder{}
	a.mu.Unlock()
	for _, r := range recs {
		r.close() // channel gone — flush every open recording
	}
	for _, viewers := range all {
		for _, b := range viewers {
			b.write(consoleFrame{T: "session-exit", Msg: "agent disconnected"})
			b.browser.Close()
		}
	}
}

var (
	regMu  sync.Mutex
	agents = map[string]*agentConn{}
)

func regSet(machineID string, a *agentConn) {
	a.machineID = machineID
	regMu.Lock()
	if old := agents[machineID]; old != nil {
		old.conn.Close()
	}
	agents[machineID] = a
	regMu.Unlock()
}

func regGet(machineID string) *agentConn {
	regMu.Lock()
	defer regMu.Unlock()
	return agents[machineID]
}

// regAll returns a snapshot of the machineID→agent registry (for the global session list).
func regAll() map[string]*agentConn {
	regMu.Lock()
	defer regMu.Unlock()
	out := make(map[string]*agentConn, len(agents))
	for k, v := range agents {
		out[k] = v
	}
	return out
}

func regDel(machineID string, a *agentConn) {
	regMu.Lock()
	if agents[machineID] == a {
		delete(agents, machineID)
	}
	regMu.Unlock()
}

// consoleTeardown drops a machine's live agent channel (used when console is disabled or the
// machine is revoked): closes browser viewers and the agent connection.
func consoleTeardown(machineID string) {
	regMu.Lock()
	a := agents[machineID]
	delete(agents, machineID)
	regMu.Unlock()
	if a != nil {
		a.closeAll()
		a.conn.Close()
	}
}

// ---- agent channel handler (fleet mTLS listener) ------------------------------------------------

// HandleConsoleChannel upgrades the agent's persistent console WebSocket (client-cert authed via
// requireClientCert) and fans its frames out to the browser viewers of each session.
func (s *Service) HandleConsoleChannel(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if m == nil {
		writeErr(w, http.StatusUnauthorized, "no machine")
		return
	}
	conn, err := agentUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(8 << 20) // 8 MiB/frame cap (file-get chunks can be large but still bounded)
	a := &agentConn{
		conn: conn, bridges: map[string][]*consoleBridge{}, owners: map[string]int64{},
		opened: map[string]time.Time{}, seen: map[string]time.Time{},
		labels: map[string]int{}, snapWaiters: map[string][]*snapWaiter{},
		recs: map[string]*consoleRecorder{},
	}
	regSet(m.ID, a)
	// Reaper: sweep this channel's sessions for idle / over-max every minute, for the life of the
	// connection. Kills past-limit resumable shells so a root session can't linger indefinitely.
	stopReaper := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stopReaper:
				return
			case <-t.C:
				a.reapExpired()
			}
		}
	}()
	// A vanished machine is noticed (its sessions and recordings closed) instead of the channel
	// waiting forever; the agent likewise drops a panel that stops pinging.
	stopPing := keepAlive(conn)
	defer func() {
		stopPing()
		close(stopReaper)
		regDel(m.ID, a)
		a.closeAll()
		conn.Close()
	}()
	for {
		var f consoleFrame
		if err := conn.ReadJSON(&f); err != nil {
			return
		}
		if f.T == "sessions-list" {
			a.syncSessions(f.Sessions) // rebuild resume after a panel restart (tmux outlived the panel)
			continue
		}
		if f.T == "snapshot-result" {
			a.deliverSnapshot(f) // one-shot screen capture (preview card, or a joining viewer's screen)
			continue
		}
		if f.T == "data" {
			a.touch(f.Session) // agent→browser output counts as activity (a long-running command isn't idle)
		}
		a.routeToBrowsers(f)
	}
}

// ---- browser console handler (main API, mounted directly on the mux) ----------------------------

// consoleRecheck is how often an open console re-checks what opening it required, so revoking,
// demoting or deleting the operator, ending or locking their session, taking the machine out of
// their scope or switching its console off cuts the shell within this time (not at helper.ConsoleMaxDuration).
var consoleRecheck = helper.ConsoleRecheck // a var so tests can shorten it

// consoleAccess checks what every console needs, at open and again every consoleRecheck while it
// stays open: a live, unlocked session with the operator role (the WS is mounted directly on the
// mux, bypassing REST RBAC — a viewer must never reach an interactive shell, even with a shared
// grant), a known machine in that user's scope, and console enabled on it. It returns the principal
// and machine, or the HTTP status and reason to refuse with.
func (s *Service) consoleAccess(token, machineID string) (*router.Principal, *Machine, int, string) {
	p, _, _ := router.Authenticate(token, false)
	if p == nil {
		return nil, nil, http.StatusUnauthorized, "unauthorized"
	}
	if !auth.RoleAtLeast(p.Role, auth.RoleOperator) {
		return nil, nil, http.StatusForbidden, "insufficient role"
	}
	m, err := s.machineByID(machineID)
	if err != nil || m == nil {
		return nil, nil, http.StatusNotFound, "unknown machine"
	}
	if !scopeAllows(p, *m) {
		return nil, nil, http.StatusForbidden, "machine out of scope"
	}
	if !m.ConsoleEnabled {
		return nil, nil, http.StatusForbidden, "console is not enabled for this machine"
	}
	return p, m, 0, ""
}

// recheckUntil calls check every interval until stop closes; the first failure (a non-empty
// reason) is passed to cut and ends the watch.
func recheckUntil(interval time.Duration, stop <-chan struct{}, check func() string, cut func(reason string)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if reason := check(); reason != "" {
				cut(reason)
				return
			}
		}
	}
}

// HandleBrowserConsole authenticates the operator (session cookie/Bearer), validates the short-lived
// step-up grant + scope + per-host enable, then bridges the browser to the machine's agent channel.
// The same access is re-checked every consoleRecheck while the console stays open.
func (s *Service) HandleBrowserConsole(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	q := r.URL.Query()
	machineID := q.Get("machine")
	p, m, code, reason := s.consoleAccess(token, machineID)
	if code != 0 {
		http.Error(w, reason, code)
		return
	}
	grantID := q.Get("grant")
	session := q.Get("session")
	if grantID == "" || session == "" {
		http.Error(w, "grant and session are required", http.StatusBadRequest)
		return
	}
	if !consoleSessionRe.MatchString(session) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}
	g, ok := takeGrant(grantID, machineID, session, p.UserID)
	if !ok {
		http.Error(w, "invalid or expired console grant", http.StatusForbidden)
		return
	}
	a := regGet(machineID)
	if a == nil {
		http.Error(w, "the machine's console agent is offline", http.StatusConflict)
		return
	}
	readonly := g.readonly

	// Interactive sessions are namespaced by the opener's user id, so an operator can only ever
	// address (open/resume/record) their OWN sessions — a client-chosen id can't collide with or
	// reattach another operator's shell. A read-only share opens the owner's namespaced session,
	// which the grant carries verbatim (takeGrant already matched it).
	effSession := session
	if !readonly {
		effSession = nsSession(p.UserID, session)
	}

	conn, err := browserUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(1 << 20) // 1 MiB/frame cap — a hostile browser can't force an unbounded alloc

	cols := clampDim(q.Get("cols"), 80)
	rows := clampDim(q.Get("rows"), 24)

	// Owner-only interactive attach (ownership persists across detach for resume); a new shell
	// counts against the per-user and per-machine session limits.
	if !readonly {
		if reason := a.claimOwner(effSession, p.UserID); reason != "" {
			conn.WriteJSON(consoleFrame{T: "error", Msg: reason})
			return
		}
	}
	b := &consoleBridge{browser: conn, session: effSession, readonly: readonly}
	first, ok := a.addBridge(effSession, b)
	if !ok {
		conn.WriteJSON(consoleFrame{T: "error", Msg: fmt.Sprintf("%d browsers are already attached to this session", helper.MaxConsoleViewers)})
		return
	}
	if !readonly {
		a.touch(effSession) // start/refresh the session's activity clock for the reaper
	}
	// Recording machines record EVERY interactive session — one continuous file per session, resumed
	// on reattach (see console_record.go). Read-only viewers add nothing: they can't produce input.
	recording := m.ConsoleRecord && !readonly
	if recording {
		a.attachRecorder(m, effSession, int(cols), int(rows), p)
	}
	events.Audit("fleet", "console_open", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Console opened on %q (session %s%s)", m.Name, effSession, roSuffix(readonly)))
	// The first viewer opens/attaches the shell; later viewers just watch. A read-only viewer never
	// causes an agent-side open (it can only ever watch an already-running session).
	if first && !readonly {
		a.writeToAgent(consoleFrame{T: "open", Session: effSession, Cols: cols, Rows: rows})
	} else if !first {
		go a.showScreen(b)
	}
	// Any viewer joining changes what the session lists show (attached / viewers / recording) — push.
	notifySessionsChanged(machineID)

	// Keep checking access while open: the first failure closes this viewer's socket, which ends
	// the read loop below and runs the normal close path.
	stopRecheck := make(chan struct{})
	defer close(stopRecheck)
	go recheckUntil(consoleRecheck, stopRecheck, func() string {
		p2, _, code, reason := s.consoleAccess(token, machineID)
		if code == 0 && p2.UserID != p.UserID {
			return "session changed"
		}
		return reason
	}, func(reason string) {
		events.Audit("fleet", "console_cut", events.SeverityWarning, p.Username, helper.GetClientIP(r),
			fmt.Sprintf("Console on %q (session %s) closed: access ended (%s)", m.Name, effSession, reason))
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "access ended: "+reason), time.Now().Add(time.Second))
		conn.Close()
	})

	defer func() {
		last := a.removeBridge(effSession, b)
		if recording {
			a.detachRecorder(effSession)
		}
		if last {
			a.writeToAgent(consoleFrame{T: "close", Session: effSession}) // detach (tmux keeps it; owner retained)
		}
		notifySessionsChanged(machineID) // …and so does one leaving (detached, viewer count, recording off)
		events.Audit("fleet", "console_close", events.SeverityInfo, p.Username, helper.GetClientIP(r),
			fmt.Sprintf("Console closed on %q (session %s)", m.Name, effSession))
	}()

	for {
		var f consoleFrame
		if err := conn.ReadJSON(&f); err != nil {
			return
		}
		if readonly {
			continue // view-only: drop EVERY browser frame (data, file-put, file-get, resize, close…)
		}
		a.relayBrowserFrame(f, effSession, func(label string) {
			events.Audit("fleet", "console_action", events.SeverityWarning, p.Username, helper.GetClientIP(r),
				fmt.Sprintf("Console on %q (session %s): %s", m.Name, effSession, label))
		})
	}
}

// relayBrowserFrame forwards one frame from an interactive browser to its own session on the agent.
// Panel-only control frames (open, …) are dropped, the session is forced to the browser's own,
// resizes are bounded and keystrokes refresh the idle clock. An action outside the terminal
// (consoleActionLabel) is audited and marked in the session's recording first: its effect isn't in
// the terminal output, so without that it would leave no trace.
func (a *agentConn) relayBrowserFrame(f consoleFrame, session string, audit func(label string)) {
	if !browserFrameTypes[f.T] {
		return
	}
	f.Session = session // never let a browser target another session
	switch f.T {
	case "resize":
		f.Cols, f.Rows = clampResize(f.Cols), clampResize(f.Rows) // bound every resize, not just open
	case "data":
		a.touch(session) // keystrokes refresh the idle clock
	}
	if label := consoleActionLabel(f); label != "" {
		audit(label)
		a.recordMarker(session, label)
	}
	a.writeToAgent(f)
}

// maxActionPath bounds the path quoted in an action's audit entry and recording marker.
const maxActionPath = 256

// consoleActionLabel describes a browser frame that writes, removes or takes files, or starts or
// stops containers, on the machine through the console's panels instead of the terminal; "" for
// everything else (keystrokes and resizes, which the recording already has, and the read-only
// panels: listings, git status, docker ps/logs, diagnostics).
func consoleActionLabel(f consoleFrame) string {
	path := f.Path
	if len(path) > maxActionPath {
		path = path[:maxActionPath] + "…"
	}
	switch f.T {
	case "file-put":
		if f.Start { // once per upload, not per chunk
			return "upload " + path
		}
	case "file-get":
		return "download " + path
	case "file-delete":
		return "delete " + path
	case "file-mkdir":
		return "create folder " + path
	case "docker":
		switch f.Action {
		case "start", "stop", "restart":
			return "docker " + f.Action + " " + path
		}
	}
	return ""
}

// browserFrameTypes is everything an interactive browser may send to its own session on the agent.
// Anything else is dropped — notably the open/sessions/snapshot control frames the panel issues
// itself. Keep in sync with ui/src/lib/console.js.
var browserFrameTypes = map[string]bool{
	"data": true, "resize": true, "close": true,
	"file-put": true, "file-get": true, "file-list": true, "file-delete": true, "file-mkdir": true,
	"ping": true, "git": true, "docker": true, "diag": true,
}

// consoleSessionRe is a valid console session id (the browser's random id, or a share link's
// namespaced "<user id>_<id>"); the agent checks the same and matches tmux names exactly.
var consoleSessionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`)

// nsSession namespaces a client-chosen session id by the owner's user id, so interactive sessions
// are private to their opener (no cross-operator reattach or id collision).
func nsSession(userID int64, s string) string {
	return strconv.FormatInt(userID, 10) + "_" + s
}

func roSuffix(ro bool) string {
	if ro {
		return ", read-only"
	}
	return ""
}

// ---- step-up grants -----------------------------------------------------------------------------

type consoleGrant struct {
	userID    int64
	machineID string
	session   string // for read-only share grants: binds the grant to a single session
	readonly  bool
	expires   time.Time
	uses      int
}

// Console grants alive at once: at most helper.MaxConsoleGrantsPerUser per user, so one operator
// can't use up the room everyone shares, and helper.MaxConsoleGrants in all. Each is minted after a
// password check and lives minutes; past a cap, minting is refused rather than any grant dropped.
var (
	consoleGrants = bounded.New[string, consoleGrant](helper.MaxConsoleGrants, bounded.Refuse)
	grantMintMu   sync.Mutex // makes the per-user count and the mint one step
)

// mintGrant returns a new grant id, or "" when the user, or everyone together, has too many alive.
func mintGrant(userID int64, machineID, session string, readonly bool, ttl time.Duration, uses int) string {
	buf := make([]byte, 24)
	rand.Read(buf)
	id := hex.EncodeToString(buf)
	now := time.Now()
	grantMintMu.Lock()
	defer grantMintMu.Unlock()
	if consoleGrants.Count(now, func(g consoleGrant) bool { return g.userID == userID }) >= helper.MaxConsoleGrantsPerUser {
		return ""
	}
	if !consoleGrants.Update(id, now, func(g *consoleGrant, _ bool) time.Time {
		*g = consoleGrant{userID: userID, machineID: machineID, session: session, readonly: readonly, expires: now.Add(ttl), uses: uses}
		return g.expires
	}) {
		return ""
	}
	return id
}

// takeGrant validates a grant for the machine (and, for a share grant, the exact session) and
// consumes one use. A read-only (share) grant is usable by another logged-in operator in scope but
// only for the single session it was minted for; a normal grant is bound to the user who minted it.
func takeGrant(id, machineID, session string, userID int64) (*consoleGrant, bool) {
	var taken *consoleGrant
	now := time.Now()
	consoleGrants.Update(id, now, func(g *consoleGrant, found bool) time.Time {
		if !found {
			return now // nothing to keep
		}
		if g.machineID != machineID || (!g.readonly && g.userID != userID) || (g.readonly && g.session != session) {
			return g.expires // not this caller's grant: left untouched
		}
		g.uses--
		c := *g
		taken = &c
		if g.uses <= 0 {
			return now
		}
		return g.expires
	})
	return taken, taken != nil
}

// ---- recording (asciinema v2 .cast) -------------------------------------------------------------

// (Session recording lives in console_record.go.)

// ---- HTTP handlers (main API, via the router) ---------------------------------------------------

// handleConsoleGrant mints a short-lived, multi-use step-up grant to open a console on a machine. Operator+ and
// in-scope; step-up (428) required. ?readonly=true mints a longer-lived, shareable view-only grant.
// POST /api/fleet/console/grant  {"machine_id":"..."}
func (s *Service) handleConsoleGrant(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	readonly := r.URL.Query().Get("readonly") == "true"
	var req struct {
		MachineID       string `json:"machine_id"`
		Session         string `json:"session"` // set when minting a read-only share grant for a live session
		CurrentPassword string `json:"currentPassword"`
		TOTPCode        string `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	m, err := s.machineByID(req.MachineID)
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return
	}
	if p == nil || !scopeAllows(p, *m) {
		router.JSONError(w, "machine out of scope", http.StatusForbidden)
		return
	}
	if !m.ConsoleEnabled {
		router.JSONError(w, "console is not enabled for this machine", http.StatusForbidden)
		return
	}
	// Step-up re-auth before handing out console access (honours the grace window — see
	// consoleStepUpGraced — so an operator isn't re-prompted on every console open).
	if status, err := s.consoleStepUpGraced(r, req.CurrentPassword, req.TOTPCode); err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	// A normal grant is multi-use within a short window so one step-up covers opening several
	// tabs + reconnects; a read-only (share) grant lives longer for handing to another operator.
	ttl, uses := helper.ConsoleGrantTTL, helper.ConsoleGrantUses
	session := ""
	if readonly {
		ttl, uses = helper.ConsoleShareGrantTTL, helper.ConsoleShareGrantUses
		// A share link may only be minted by the operator who currently OWNS the session, and it is
		// bound to that owner's namespaced session id — so one operator can't share (or even address)
		// another operator's shell.
		if req.Session == "" || !consoleSessionRe.MatchString(req.Session) {
			router.JSONError(w, "a valid session is required to create a share link", http.StatusBadRequest)
			return
		}
		session = nsSession(p.UserID, req.Session)
		if a := regGet(m.ID); a == nil || !a.isOwner(session, p.UserID) {
			router.JSONError(w, "you can only share a console session you currently own", http.StatusForbidden)
			return
		}
	}
	id := mintGrant(p.UserID, m.ID, session, readonly, ttl, uses)
	if id == "" {
		router.JSONError(w, "too many console grants right now, try again shortly", http.StatusServiceUnavailable)
		return
	}
	events.Audit("fleet", "console_grant", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Console grant issued for %q%s", m.Name, roSuffix(readonly)))
	router.JSON(w, map[string]any{"grant": id, "readonly": readonly, "session": session, "expiresInSec": int(ttl.Seconds())})
}

// grantAllTargets is the machines a grant-all request gets grants for: each once, and no more than
// a user may hold grants for (each is a lookup, so a long list of made-up ids is cut short too).
func grantAllTargets(ids []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		if len(out) == helper.MaxConsoleGrantsPerUser {
			break
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// handleConsoleGrantAll mints console grants for several machines after a SINGLE step-up, so the
// global console can attach every live session at once without prompting once per machine. Each
// grant is the same short-lived, multi-use kind as a normal grant. Only in-scope, console-enabled
// machines get one; others are silently skipped.
// POST /api/fleet/console/grant-all {"machine_ids":[...],"currentPassword","totpCode"} → {"grants":{machineID:grant}}
func (s *Service) handleConsoleGrantAll(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	var req struct {
		MachineIDs      []string `json:"machine_ids"`
		CurrentPassword string   `json:"currentPassword"`
		TOTPCode        string   `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if p == nil {
		router.JSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Step-up re-auth once, before handing out any console access (honours the grace window, so
	// re-entering the console within it doesn't prompt again).
	if status, err := s.consoleStepUpGraced(r, req.CurrentPassword, req.TOTPCode); err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	ttl, uses := helper.ConsoleGrantTTL, helper.ConsoleGrantUses
	grants := map[string]string{}
	for _, mid := range grantAllTargets(req.MachineIDs) {
		m, err := s.machineByID(mid)
		if err != nil || m == nil || !scopeAllows(p, *m) || !m.ConsoleEnabled {
			continue
		}
		if id := mintGrant(p.UserID, m.ID, "", false, ttl, uses); id != "" {
			grants[m.ID] = id
		}
	}
	events.Audit("fleet", "console_grant", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Console grants issued for %d machine(s)", len(grants)))
	router.JSON(w, map[string]any{"grants": grants})
}

// handleConsoleToggle enables/disables the console for a machine (admin). Enabling requires step-up.
// Persists the per-host flags AND pushes set-console to the agent; disabling tears live sessions
// down. POST /api/fleet/console/toggle  {"machine_id":"...","enabled":true,"record":false}
func (s *Service) handleConsoleToggle(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	var req struct {
		MachineID       string `json:"machine_id"`
		Enabled         bool   `json:"enabled"`
		Record          bool   `json:"record"`
		CurrentPassword string `json:"currentPassword"`
		TOTPCode        string `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	m, err := s.machineByID(req.MachineID)
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return
	}
	if req.Enabled { // turning a remote shell ON is the sensitive direction
		if status, err := s.consoleStepUp(r, req.CurrentPassword, req.TOTPCode); err != nil {
			router.JSONError(w, err.Error(), status)
			return
		}
	}
	if err := s.setConsoleEnabled(m.ID, req.Enabled, req.Record); err != nil {
		router.JSONError(w, "could not update machine", http.StatusInternalServerError)
		return
	}
	payload, _ := json.Marshal(map[string]bool{"enabled": req.Enabled})
	s.Enqueue(m.ID, "set-console", payload) // push the flag to the agent (allowlisted)
	if !req.Enabled {
		consoleTeardown(m.ID) // drop any live channel/sessions immediately
	}
	events.Audit("fleet", "console_toggle", events.SeverityWarning,
		principalName(p), helper.GetClientIP(r),
		fmt.Sprintf("Console %s for %q (recording=%v)", enabledWord(req.Enabled), m.Name, req.Record))
	router.JSON(w, map[string]bool{"enabled": req.Enabled, "record": req.Record})
}

// handleConsoleSessions lists the live console sessions for a machine (for the tabs UI).
// GET /api/fleet/console/sessions?machine_id=...
func (s *Service) handleConsoleSessions(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	machineID := r.URL.Query().Get("machine_id")
	if machineID == "" { // no machine → the global list (all accessible machines)
		s.handleAllSessions(w, r, p)
		return
	}
	m, err := s.machineByID(machineID)
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return
	}
	if p == nil || !scopeAllows(p, *m) {
		router.JSONError(w, "machine out of scope", http.StatusForbidden)
		return
	}
	if !m.ConsoleEnabled {
		router.JSONError(w, "console is not enabled for this machine", http.StatusForbidden)
		return
	}
	sessions := []sessInfo{}
	online := false
	if a := regGet(machineID); a != nil {
		online = true
		// Live query: ask the agent what's actually running right now and wait for the reconciled
		// reply, so the list reflects real tmux state (no stale ghosts) rather than a cached map.
		a.requestSessions(1500 * time.Millisecond)
		sessions = collectSessions(a, p.UserID, "", "")
	}
	router.JSON(w, map[string]any{"online": online, "sessions": sessions})
}

// sessInfo is one resumable session as shown to the UI (per-machine list, global list, cards).
type sessInfo struct {
	ID          string `json:"id"`                     // client-facing id (no nsSession prefix)
	Label       int    `json:"label"`                  // friendly per-machine "Session N"
	Attached    bool   `json:"attached"`               // at least one viewer connected
	Viewers     int    `json:"viewers"`                // live viewer count
	Recording   bool   `json:"recording"`              // a recording is being written right now
	MachineID   string `json:"machine_id,omitempty"`   // set on the global list
	MachineName string `json:"machine_name,omitempty"` // set on the global list
}

// collectSessions returns the caller's own sessions on one agent. Ownership (a.owners) persists
// across a browser detach — the tmux shell lives on for resume — so we list by owner, not by live
// bridge. Owner-scoped: never discloses another operator's sessions. The owners key is the
// SERVER-namespaced id ("<userID>_<client id>"); we return the client-facing id (prefix stripped)
// so a reattach re-namespaces to the SAME session. machineID/Name are set only for the global list.
func collectSessions(a *agentConn, userID int64, machineID, machineName string) []sessInfo {
	out := []sessInfo{}
	prefix := strconv.FormatInt(userID, 10) + "_"
	a.mu.Lock()
	for id, uid := range a.owners {
		if uid != userID {
			continue
		}
		si := sessInfo{
			ID:          strings.TrimPrefix(id, prefix),
			Label:       a.labels[id],
			Attached:    len(a.bridges[id]) > 0,
			Viewers:     len(a.bridges[id]),
			Recording:   a.recs[id] != nil,
			MachineID:   machineID,
			MachineName: machineName,
		}
		out = append(out, si)
	}
	a.mu.Unlock()
	return out
}

// handleAllSessions aggregates the caller's sessions across EVERY accessible, console-enabled
// machine (for the global console + the dashboard "resume" strip). It live-queries each agent in
// parallel so the combined list reflects real tmux state. GET /api/fleet/console/sessions (no id).
func (s *Service) handleAllSessions(w http.ResponseWriter, r *http.Request, p *router.Principal) {
	router.JSON(w, map[string]any{"sessions": s.globalSessions(p, true)})
}

// globalSessions returns the caller's sessions across every accessible, console-enabled machine.
// When live is true it first live-queries each agent in parallel (fresh, for the HTTP endpoint and
// the initial WS push); when false it reads the already-reconciled owner maps (cheap, for the push
// that fires on a session change — the change itself just reconciled the relevant agent).
func (s *Service) globalSessions(p *router.Principal, live bool) []sessInfo {
	if p == nil {
		return []sessInfo{}
	}
	type entry struct {
		a    *agentConn
		id   string
		name string
	}
	var accessible []entry
	for mid, a := range regAll() {
		m, err := s.machineByID(mid)
		if err != nil || m == nil || !scopeAllows(p, *m) || !m.ConsoleEnabled {
			continue
		}
		accessible = append(accessible, entry{a, m.ID, m.Name})
	}
	if live {
		var wg sync.WaitGroup
		for _, e := range accessible {
			wg.Add(1)
			go func(a *agentConn) { defer wg.Done(); a.requestSessions(1200 * time.Millisecond) }(e.a)
		}
		wg.Wait()
	}
	sessions := []sessInfo{}
	for _, e := range accessible {
		sessions = append(sessions, collectSessions(e.a, p.UserID, e.id, e.name)...)
	}
	return sessions
}

// handleConsoleKill destroys one of the caller's own sessions (the "close session" button).
// It sends the agent a kill frame; the agent tears down the tmux session and replies session-exit,
// which frees the owner. Owner-scoped. POST /api/fleet/console/kill {"machine_id","session"}
func (s *Service) handleConsoleKill(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	var req struct {
		MachineID string `json:"machine_id"`
		Session   string `json:"session"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	m, err := s.machineByID(req.MachineID)
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return
	}
	if p == nil || !scopeAllows(p, *m) {
		router.JSONError(w, "machine out of scope", http.StatusForbidden)
		return
	}
	a := regGet(req.MachineID)
	if a == nil {
		router.JSONError(w, "the machine's console agent is offline", http.StatusConflict)
		return
	}
	eff := nsSession(p.UserID, req.Session) // only ever kill your OWN session
	a.mu.Lock()
	owner := a.owners[eff]
	a.mu.Unlock()
	if owner != p.UserID {
		router.JSONError(w, "session out of scope", http.StatusForbidden)
		return
	}
	a.writeToAgent(consoleFrame{T: "kill", Session: eff})
	events.Audit("fleet", "console_kill", events.SeverityInfo, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Console session killed on %q (session %s)", m.Name, eff))
	router.JSON(w, map[string]bool{"ok": true})
}

// handleConsoleSnapshot captures a session's current screen (one-shot, for a preview card).
// GET /api/fleet/console/snapshot?machine_id=&session=  → {"data": "<base64 screen>"}
func (s *Service) handleConsoleSnapshot(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	machineID := r.URL.Query().Get("machine_id")
	clientSession := r.URL.Query().Get("session")
	m, err := s.machineByID(machineID)
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return
	}
	if p == nil || !scopeAllows(p, *m) {
		router.JSONError(w, "machine out of scope", http.StatusForbidden)
		return
	}
	if !m.ConsoleEnabled {
		router.JSONError(w, "console is not enabled for this machine", http.StatusForbidden)
		return
	}
	a := regGet(machineID)
	if a == nil {
		router.JSONError(w, "the machine's console agent is offline", http.StatusConflict)
		return
	}
	eff := nsSession(p.UserID, clientSession) // only ever snapshot your OWN session
	a.mu.Lock()
	owner := a.owners[eff]
	a.mu.Unlock()
	if owner != p.UserID {
		router.JSONError(w, "session out of scope", http.StatusForbidden)
		return
	}
	data, _ := a.requestSnapshot(eff, 2*time.Second) // empty on timeout — the card just shows no preview
	router.JSON(w, map[string]any{"data": data})
}

func principalName(p *router.Principal) string {
	if p == nil {
		return ""
	}
	return p.Username
}

func enabledWord(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// ---- small helpers ------------------------------------------------------------------------------

func parseIntDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

// clampDim parses a terminal dimension from the query and bounds it to [1,1000] before the uint16
// conversion, so an oversized/negative value can never overflow or truncate.
func clampDim(s string, def int) uint16 {
	n := parseIntDefault(s, def)
	if n < 1 {
		return 1
	}
	if n > 1000 {
		return 1000
	}
	return uint16(n) // here 1 <= n <= 1000, so the conversion cannot overflow
}

// clampResize bounds a resize frame's dimension to [1,1000].
func clampResize(v uint16) uint16 {
	if v < 1 {
		return 1
	}
	if v > 1000 {
		return 1000
	}
	return v
}

func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "x"
	}
	return string(out)
}
