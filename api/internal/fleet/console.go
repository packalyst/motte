package fleet

// Browser console — the panel side (roadmap point 7). Two WebSocket hops bridged in-process:
//
//	browser ──(main API, cookie auth + RBAC + scope + step-up grant)──► panel ◄──(fleet mTLS
//	                                                                              listener)── agent
//
// The agent dials a persistent console channel (HandleConsoleChannel, client-cert authed) that
// multiplexes many sessions by id. A browser opens a console WS (HandleBrowserConsole) carrying a
// one-time step-up grant; the panel registers it as a viewer of a session and relays frames to the
// machine's agent channel. Read-only viewers receive output but their input is dropped. Output can
// be tee'd to an asciinema recording when the host has it enabled. Every open/close is audited.
//
// This is a full interactive shell — deliberately separate from the strict command allowlist — so
// it is gated hard: per-host enable (DB + agent flag), RBAC+scope, step-up, audit, recording.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"api/internal/auth"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/settings"

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

// consoleFrame mirrors the agent's wire protocol (JSON; binary is base64 in Data).
type consoleFrame struct {
	T       string `json:"t"`
	Session string `json:"session"`
	Cols    uint16 `json:"cols,omitempty"`
	Rows    uint16 `json:"rows,omitempty"`
	Data    string `json:"data,omitempty"`
	Path    string `json:"path,omitempty"`
	EOF     bool   `json:"eof,omitempty"`
	Msg     string `json:"msg,omitempty"`
}

var (
	agentUpgrader   = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }} // mTLS authenticates
	browserUpgrader = websocket.Upgrader{CheckOrigin: consoleSameOrigin}
)

func consoleSameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true // non-browser client; the session+grant is the real gate
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return len(o) > len(host) && o[len(o)-len(host):] == host
}

// ---- agent channel registry ---------------------------------------------------------------------

type consoleBridge struct {
	browser  *websocket.Conn
	writeMu  sync.Mutex
	session  string
	readonly bool
	rec      *consoleRecorder
}

func (b *consoleBridge) write(f consoleFrame) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	_ = b.browser.WriteJSON(f)
}

type agentConn struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	bridges map[string][]*consoleBridge // session id → viewers
}

func (a *agentConn) writeToAgent(f consoleFrame) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_ = a.conn.WriteJSON(f)
}

func (a *agentConn) addBridge(session string, b *consoleBridge) (first bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	first = len(a.bridges[session]) == 0
	a.bridges[session] = append(a.bridges[session], b)
	return first
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

// routeToBrowsers forwards one agent frame to every viewer of its session (teeing output to the
// recorder), and tears the session down on session-exit.
func (a *agentConn) routeToBrowsers(f consoleFrame) {
	a.mu.Lock()
	viewers := append([]*consoleBridge(nil), a.bridges[f.Session]...)
	a.mu.Unlock()
	for _, b := range viewers {
		b.write(f)
		if f.T == "data" && b.rec != nil {
			b.rec.writeOutput(f.Data)
		}
	}
	if f.T == "session-exit" {
		a.mu.Lock()
		delete(a.bridges, f.Session)
		a.mu.Unlock()
	}
}

func (a *agentConn) closeAll() {
	a.mu.Lock()
	all := a.bridges
	a.bridges = map[string][]*consoleBridge{}
	a.mu.Unlock()
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
	a := &agentConn{conn: conn, bridges: map[string][]*consoleBridge{}}
	regSet(m.ID, a)
	defer func() {
		regDel(m.ID, a)
		a.closeAll()
		conn.Close()
	}()
	for {
		var f consoleFrame
		if err := conn.ReadJSON(&f); err != nil {
			return
		}
		a.routeToBrowsers(f)
	}
}

// ---- browser console handler (main API, mounted directly on the mux) ----------------------------

// HandleBrowserConsole authenticates the operator (session cookie/Bearer), validates the one-time
// step-up grant + scope + per-host enable, then bridges the browser to the machine's agent channel.
func (s *Service) HandleBrowserConsole(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	p, ok := router.ResolvePrincipal(token)
	if !ok || p == nil || p.Locked {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	machineID := q.Get("machine")
	grantID := q.Get("grant")
	session := q.Get("session")
	if machineID == "" || grantID == "" || session == "" {
		http.Error(w, "machine, grant and session are required", http.StatusBadRequest)
		return
	}
	g, ok := takeGrant(grantID, machineID, p.UserID)
	if !ok {
		http.Error(w, "invalid or expired console grant", http.StatusForbidden)
		return
	}
	m, err := s.machineByID(machineID)
	if err != nil || m == nil {
		http.Error(w, "unknown machine", http.StatusNotFound)
		return
	}
	if !scopeAllows(p, *m) {
		http.Error(w, "machine out of scope", http.StatusForbidden)
		return
	}
	if !m.ConsoleEnabled {
		http.Error(w, "console is not enabled for this machine", http.StatusForbidden)
		return
	}
	a := regGet(machineID)
	if a == nil {
		http.Error(w, "the machine's console agent is offline", http.StatusConflict)
		return
	}

	conn, err := browserUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	cols := clampDim(q.Get("cols"), 80)
	rows := clampDim(q.Get("rows"), 24)
	readonly := g.readonly

	var rec *consoleRecorder
	if m.ConsoleRecord && !readonly {
		rec = newConsoleRecorder(m, session, int(cols), int(rows))
	}
	b := &consoleBridge{browser: conn, session: session, readonly: readonly, rec: rec}
	first := a.addBridge(session, b)
	events.Audit("fleet", "console_open", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Console opened on %q (session %s%s)", m.Name, session, roSuffix(readonly)))
	// The first viewer opens/attaches the shell; later viewers just watch the same session.
	if first {
		a.writeToAgent(consoleFrame{T: "open", Session: session, Cols: cols, Rows: rows})
	}

	defer func() {
		last := a.removeBridge(session, b)
		if rec != nil {
			rec.close()
		}
		if last {
			a.writeToAgent(consoleFrame{T: "close", Session: session}) // detach (tmux keeps it)
		}
		events.Audit("fleet", "console_close", events.SeverityInfo, p.Username, helper.GetClientIP(r),
			fmt.Sprintf("Console closed on %q (session %s)", m.Name, session))
	}()

	for {
		var f consoleFrame
		if err := conn.ReadJSON(&f); err != nil {
			return
		}
		f.Session = session // never let a browser target another session
		if readonly && (f.T == "data" || f.T == "file-put") {
			continue // view-only: drop input
		}
		a.writeToAgent(f)
	}
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
	readonly  bool
	expires   time.Time
	uses      int
}

var (
	grantMu sync.Mutex
	grants  = map[string]*consoleGrant{}
)

func mintGrant(userID int64, machineID string, readonly bool, ttl time.Duration, uses int) string {
	buf := make([]byte, 24)
	rand.Read(buf)
	id := hex.EncodeToString(buf)
	grantMu.Lock()
	now := time.Now()
	for k, g := range grants { // sweep expired
		if now.After(g.expires) {
			delete(grants, k)
		}
	}
	grants[id] = &consoleGrant{userID: userID, machineID: machineID, readonly: readonly, expires: now.Add(ttl), uses: uses}
	grantMu.Unlock()
	return id
}

// takeGrant validates a grant for the machine and consumes one use. A read-only (share) grant is
// usable by any logged-in operator in scope; a normal grant is bound to the user who minted it.
func takeGrant(id, machineID string, userID int64) (*consoleGrant, bool) {
	grantMu.Lock()
	defer grantMu.Unlock()
	g := grants[id]
	if g == nil || time.Now().After(g.expires) || g.machineID != machineID {
		return nil, false
	}
	if !g.readonly && g.userID != userID {
		return nil, false
	}
	g.uses--
	if g.uses <= 0 {
		delete(grants, id)
	}
	return g, true
}

// ---- recording (asciinema v2 .cast) -------------------------------------------------------------

type consoleRecorder struct {
	f     *os.File
	start time.Time
	mu    sync.Mutex
}

func recordDir() string {
	d, _ := settings.GetSetting("console_record_dir")
	if d == "" {
		d = "data/console-recordings"
	}
	return d
}

func newConsoleRecorder(m *Machine, session string, cols, rows int) *consoleRecorder {
	dir := recordDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil
	}
	name := fmt.Sprintf("%s-%s-%d.cast", sanitize(m.ID), sanitize(session), time.Now().Unix())
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return nil
	}
	hdr := map[string]any{"version": 2, "width": cols, "height": rows, "timestamp": time.Now().Unix()}
	b, _ := json.Marshal(hdr)
	f.Write(append(b, '\n'))
	events.Audit("fleet", "console_record", events.SeverityInfo, "", "",
		fmt.Sprintf("Recording console session %s for %q → %s", session, m.Name, name))
	return &consoleRecorder{f: f, start: time.Now()}
}

func (c *consoleRecorder) writeOutput(b64 string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// asciinema event: [elapsed, "o", decoded-output]. We store the base64 output as a string —
	// decode so the cast replays correctly.
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return
	}
	ev, _ := json.Marshal([]any{time.Since(c.start).Seconds(), "o", string(data)})
	c.f.Write(append(ev, '\n'))
}

func (c *consoleRecorder) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.f.Close()
}

// ---- HTTP handlers (main API, via the router) ---------------------------------------------------

// handleConsoleGrant mints a one-time step-up grant to open a console on a machine. Operator+ and
// in-scope; step-up (428) required. ?readonly=true mints a longer-lived, shareable view-only grant.
// POST /api/fleet/console/grant  {"machine_id":"..."}
func (s *Service) handleConsoleGrant(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	readonly := r.URL.Query().Get("readonly") == "true"
	var req struct {
		MachineID       string `json:"machine_id"`
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
	// Step-up re-auth before handing out console access.
	if status, err := s.consoleStepUp(r, req.CurrentPassword, req.TOTPCode); err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	// A normal grant is multi-use within a short window so one step-up covers opening several
	// tabs + reconnects; a read-only (share) grant lives longer for handing to another operator.
	ttl, uses := 5*time.Minute, 50
	if readonly {
		ttl, uses = 30*time.Minute, 200
	}
	id := mintGrant(p.UserID, m.ID, readonly, ttl, uses)
	events.Audit("fleet", "console_grant", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Console grant issued for %q%s", m.Name, roSuffix(readonly)))
	router.JSON(w, map[string]any{"grant": id, "readonly": readonly, "expiresInSec": int(ttl.Seconds())})
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
	m, err := s.machineByID(machineID)
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return
	}
	if p == nil || !scopeAllows(p, *m) {
		router.JSONError(w, "machine out of scope", http.StatusForbidden)
		return
	}
	sessions := []string{}
	online := false
	if a := regGet(machineID); a != nil {
		online = true
		a.mu.Lock()
		for id := range a.bridges {
			sessions = append(sessions, id)
		}
		a.mu.Unlock()
	}
	router.JSON(w, map[string]any{"online": online, "sessions": sessions})
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
