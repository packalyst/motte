package fleet

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"api/internal/auth"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// allowedCommands is the ONLY set of actions the panel can tell an agent to run.
// Never a shell string. The agent independently re-checks this set before acting,
// so a compromised panel row still can't make the agent run arbitrary code.
var allowedCommands = map[string]bool{
	"block":          true,
	"unblock":        true,
	"apply-updates":  true,
	"restart":        true,
	"rescan":         true, // re-run the Trivy CVE scan now (don't wait for the interval)
	"sync-blocks":    true, // replace the machine's panel-pushed blocklist with the panel's current one
	"clear-blocks":   true, // empty the machine's panel-pushed blocklist (leaves CrowdSec/manual bans)
	"fix-packages":   true, // targeted OS-package upgrades for selected CVEs
	"update-kernel":  true, // install newest kernel meta-packages (+ reboot separately)
	"set-dry-run":    true, // flip enforcement on/off (dry-run) live
	"update-agent":   true, // self-update the wgscout binary to the latest verified release
	"set-log-level":  true, // flip agent+sub-agent verbosity live (quiet|debug)
	"set-panel-port": true, // tell the agent the panel's mTLS port changed (reconnect)
	"set-console":    true, // enable/disable the interactive console channel (point 7)
	"list-dirs":      true, // one folder's sub-folder names, for the scan dialog (dirs.go)
	"set-tool":       true, // turn CrowdSec / osquery / vulnerability scanning on or off
}

// confirmCommands are the destructive / security-impacting actions the panel will only
// enqueue after STEP-UP re-authentication (the operator re-entering their current password).
// They form the middle tier of the command guardrail:
//
//	BLOCK   — not in allowedCommands; Enqueue refuses it outright.
//	CONFIRM — listed here; requires step-up, then enqueued.
//	ALLOW   — any other allowlisted command; enqueued directly.
//
// Every operator-initiated enqueue is audit-logged (who, from where, which tier), regardless.
var confirmCommands = map[string]bool{
	"apply-updates": true, // system package upgrades — can break the host or force a reboot
	"update-kernel": true, // installs a new kernel; reboot to activate
	"restart":       true, // restarts tools or the whole host
	"update-agent":  true, // swaps the wgscout binary and restarts the service
	"set-dry-run":   true, // flips enforcement on/off — turning it OFF removes protection
	"clear-blocks":  true, // empties the machine's panel-pushed blocklist
	"set-tool":      true, // turning a security tool off removes that protection
}

// requiresStepUp reports whether ctype is a confirm-tier command.
func requiresStepUp(ctype string) bool { return confirmCommands[ctype] }

// panelInternalCommands are agent-management actions the panel issues through its own
// admin/system flows (the panel-port watcher, the console toggle, push-blocks, log-level).
// On the generic operator command endpoint they are gated to admin+: an operator could
// otherwise e.g. set-panel-port to a dead port and strand the agent, or push an arbitrary
// sync-blocks payload. The dedicated flows call s.Enqueue/enqueueGuarded directly and bypass
// this gate.
var panelInternalCommands = map[string]bool{
	"set-panel-port": true,
	"set-console":    true,
	"set-log-level":  true,
	"sync-blocks":    true,
	"list-dirs":      true, // through POST /dirs only, which waits for and removes the request
	"set-tool":       true, // which security tools run on a machine is an admin decision
}

// gatePanelInternalCommand blocks a panel-internal command type on the generic operator
// endpoint unless the caller is admin or owner. Returns false (and writes 403) when blocked.
func gatePanelInternalCommand(w http.ResponseWriter, r *http.Request, ctype string) bool {
	if !panelInternalCommands[ctype] {
		return true
	}
	p := router.CurrentUser(r)
	if p == nil || (p.Role != "admin" && p.Role != "owner") {
		router.JSONError(w, "only admins may issue agent-management commands", http.StatusForbidden)
		return false
	}
	return true
}

// actingAdmin resolves the operator behind an authenticated panel request (for audit
// attribution and step-up verification) from the principal the router injected. Returns
// ("", 0) when there is none; callers that require step-up treat that as a failure.
func (s *Service) actingAdmin(r *http.Request) (string, int64) {
	if p := router.CurrentUser(r); p != nil {
		return p.Username, p.UserID
	}
	return "", 0
}

// verifyCommandStepUp performs step-up re-authentication ONCE for a confirm-tier command. It
// returns (0, nil) when step-up passed or isn't required, else a 428 status + message to relay
// (never 401, which the client treats as a session expiry). Factored out so a bulk run verifies
// a single time — a replay-protected TOTP code cannot be reused once per host.
func (s *Service) verifyCommandStepUp(r *http.Request, ctype, currentPassword, currentTOTP string) (int, error) {
	if !requiresStepUp(ctype) {
		return 0, nil
	}
	return s.verifyStepUp(r, ctype, currentPassword, currentTOTP)
}

// verifyStepUp requires a step-up for `what` (a command, or a sensitive part of one): passes
// inside the fleet step-up grace window, else needs the operator's password (+ TOTP).
func (s *Service) verifyStepUp(r *http.Request, ctype, currentPassword, currentTOTP string) (int, error) {
	actor, userID := s.actingAdmin(r)
	ip := helper.GetClientIP(r)
	authSvc := auth.GetService()
	if authSvc == nil || userID == 0 {
		events.Audit("fleet", "command_denied", events.SeverityWarning, actor, ip,
			fmt.Sprintf("Command %q denied: operator could not be verified for step-up", ctype))
		return http.StatusPreconditionRequired, fmt.Errorf("step-up re-authentication required")
	}
	// Inside the shared fleet step-up grace window (from a recent console open or command)? Pass
	// without prompting, and slide the window — so administering a fleet isn't a password per action.
	if recentFleetStepUp(userID) {
		touchStepUpGrace(userID)
		return 0, nil
	}
	if currentPassword == "" {
		// Benign first attempt — the UI hasn't prompted yet. Signal step-up, don't audit.
		return http.StatusPreconditionRequired, fmt.Errorf("step-up re-authentication required")
	}
	if err := authSvc.VerifyStepUp(userID, currentPassword, currentTOTP); err != nil {
		if errors.Is(err, auth.ErrStepUpTOTPRequired) {
			return http.StatusPreconditionRequired, fmt.Errorf("two-factor authentication code required")
		}
		events.Audit("fleet", "command_denied", events.SeverityWarning, actor, ip,
			fmt.Sprintf("Command %q denied: step-up re-authentication failed", ctype))
		return http.StatusPreconditionRequired, fmt.Errorf("step-up re-authentication failed")
	}
	touchStepUpGrace(userID)
	return 0, nil
}

// enqueueCore applies the per-machine scope check + online check + allowlist (block tier) + audit,
// then enqueues. The online check keeps a person's command from waiting in the queue and running
// whenever an offline machine reconnects; the panel's own messages (set-console, set-panel-port)
// call Enqueue directly and do wait for the machine.
// It does NOT do step-up — callers verify that first (enqueueGuarded for one machine, the bulk
// handler once for many). Returns 403 (out of scope), 409 (offline), 400 (not allowlisted) or 200.
func (s *Service) enqueueCore(r *http.Request, machineID, ctype string, payload json.RawMessage) (string, int, error) {
	actor, _ := s.actingAdmin(r)
	ip := helper.GetClientIP(r)
	if !s.machineAllowed(r, machineID) {
		events.Audit("fleet", "command_denied", events.SeverityWarning, actor, ip,
			fmt.Sprintf("Command %q on %s denied: outside the operator's machine scope", ctype, machineID))
		return "", http.StatusForbidden, fmt.Errorf("your scope does not include this machine")
	}
	if !linkOnline(machineID) {
		return "", http.StatusConflict, fmt.Errorf("the machine is offline — commands can only be sent to machines that are online")
	}
	if err := validateCommandPayload(ctype, payload); err != nil {
		return "", http.StatusBadRequest, err
	}
	id, err := s.enqueue(machineID, ctype, payload, commandTTL)
	if err != nil {
		events.Audit("fleet", "command_blocked", events.SeverityWarning, actor, ip,
			fmt.Sprintf("Command %q on %s rejected: %v", ctype, machineID, err))
		return "", http.StatusBadRequest, err
	}
	sev := events.SeverityInfo
	if requiresStepUp(ctype) {
		sev = events.SeverityWarning
	}
	events.Audit("fleet", "command_"+ctype, sev, actor, ip,
		fmt.Sprintf("Command %q queued for machine %s", ctype, machineID))
	return id, http.StatusOK, nil
}

// enqueueGuarded applies the command guardrail (step-up for confirm-tier, then scope + allowlist +
// audit) and enqueues for ONE machine. Returns the HTTP status the caller should send.
func (s *Service) enqueueGuarded(r *http.Request, machineID, ctype, currentPassword, currentTOTP string, payload json.RawMessage) (string, int, error) {
	if status, err := s.verifyCommandStepUp(r, ctype, currentPassword, currentTOTP); err != nil {
		return "", status, err
	}
	return s.enqueueCore(r, machineID, ctype, payload)
}

// Command is one queued instruction for a machine.
type Command struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type commandResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
}

func newCommandID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// commandTTL: a command a person runs must reach the machine within this, or it expires and never
// runs — so it can't fire by surprise when an offline machine reconnects much later.
const commandTTL = 15 * time.Minute

// Enqueue adds an allowlisted command for a machine that waits until the machine picks it up, with
// no expiry. For the panel's own messages (set-console, set-panel-port) that an offline machine must
// still get when it returns; a person's command goes through enqueueCore, which sets commandTTL.
func (s *Service) Enqueue(machineID, ctype string, payload json.RawMessage) (string, error) {
	return s.enqueue(machineID, ctype, payload, 0)
}

// enqueue inserts the command; ttl > 0 sets when it expires if still undelivered.
func (s *Service) enqueue(machineID, ctype string, payload json.RawMessage, ttl time.Duration) (string, error) {
	if !allowedCommands[ctype] {
		return "", fmt.Errorf("command %q not allowed", ctype)
	}
	now := time.Now().UTC()
	var expires any // NULL: never expires
	if ttl > 0 {
		expires = now.Add(ttl).Format(time.RFC3339)
	}
	id := newCommandID()
	_, err := s.db.Exec(
		`INSERT INTO fleet_commands (id, machine_id, type, payload, status, created_at, expires_at) VALUES (?,?,?,?, 'pending', ?, ?)`,
		id, machineID, ctype, string(payload), now.Format(time.RFC3339), expires,
	)
	if err == nil {
		ringLink(machineID)
	}
	return id, err
}

// expirePending marks a machine's undelivered commands whose time ran out as expired. It reports
// whether any changed.
func (s *Service) expirePending(machineID string) bool {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`UPDATE fleet_commands SET status='expired', done_at=?
		WHERE machine_id = ? AND status = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?`, now, machineID, now)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// MachineCommand is one queued command with its lifecycle, for the admin command log.
type MachineCommand struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Status    string `json:"status"` // pending | delivered | done | error | expired
	Result    string `json:"result,omitempty"`
	CreatedAt string `json:"created_at"`
	DoneAt    string `json:"done_at,omitempty"`
}

// ListMachineCommands returns a machine's most recent commands (newest first).
func (s *Service) ListMachineCommands(machineID string, limit int) ([]MachineCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	s.expirePending(machineID) // an offline machine never polls, so expire here too for the log
	rows, err := s.db.Query(
		`SELECT id, type, status, result, created_at, done_at FROM fleet_commands
		 WHERE machine_id = ? AND type != 'list-dirs' ORDER BY created_at DESC LIMIT ?`, machineID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MachineCommand{}
	for rows.Next() {
		var c MachineCommand
		var result, doneAt sql.NullString
		if err := rows.Scan(&c.ID, &c.Type, &c.Status, &result, &c.CreatedAt, &doneAt); err != nil {
			return nil, err
		}
		c.Result, c.DoneAt = result.String, doneAt.String
		out = append(out, c)
	}
	return out, rows.Err()
}

// broadcastCommands pushes a machine's command log over the fleet channel so the
// detail page updates live (queue / deliver / ack) without polling. No-op when no
// broadcaster is wired.
func (s *Service) broadcastCommands(machineID string) {
	if s.broadcast == nil {
		return
	}
	if cmds, err := s.ListMachineCommands(machineID, 20); err == nil {
		s.scopedBroadcast(machineID, "fleet", map[string]any{"machine_id": machineID, "commands": cmds})
	}
}

// handleMachineCommands (GET /api/fleet/machine/commands?machine_id=) — the command log.
func (s *Service) handleMachineCommands(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("machine_id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "machine_id required")
		return
	}
	if !s.requireMachineAccess(w, r, id) {
		return
	}
	cmds, err := s.ListMachineCommands(id, 20)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, cmds)
}

// HandleDeregister (POST, mTLS) — the agent calls this while uninstalling, so the panel
// flags the machine as uninstalled (shown in the list, delete to remove).
func (s *Service) HandleDeregister(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if err := s.MarkUninstalled(m.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HandleCommands (GET, mTLS) returns this machine's pending commands and marks
// them delivered. The machine comes from the client cert.
func (s *Service) HandleCommands(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if s.expirePending(m.ID) {
		s.broadcastCommands(m.ID)
	}
	rows, err := s.db.Query(
		`SELECT id, type, payload FROM fleet_commands WHERE machine_id = ? AND status = 'pending'
		 AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at`, m.ID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	cmds := []Command{}
	ids := []string{}
	for rows.Next() {
		var c Command
		var payload sql.NullString
		if err := rows.Scan(&c.ID, &c.Type, &payload); err != nil {
			continue
		}
		if payload.Valid && payload.String != "" {
			c.Payload = json.RawMessage(payload.String)
		}
		cmds = append(cmds, c)
		ids = append(ids, c.ID)
	}
	rows.Close()
	// Mark delivered ONLY the rows we actually returned (by id) — never a blanket
	// "all pending for this machine". A command enqueued in the SELECT→UPDATE window,
	// or one whose Scan failed above, stays pending so it reaches the agent next poll
	// instead of being silently dropped as delivered.
	if len(ids) > 0 {
		q := `UPDATE fleet_commands SET status='delivered', delivered_at=? WHERE id IN (?` +
			strings.Repeat(",?", len(ids)-1) + `)`
		args := make([]any, 0, len(ids)+1)
		args = append(args, time.Now().UTC().Format(time.RFC3339))
		for _, id := range ids {
			args = append(args, id)
		}
		_, _ = s.db.Exec(q, args...)
		s.broadcastCommands(m.ID) // pending -> delivered, push to a watching detail page
	}
	writeJSON(w, http.StatusOK, cmds)
}

// HandleCommandAck (POST, mTLS) records execution results for this machine's commands.
func (s *Service) HandleCommandAck(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	var body struct {
		Results []commandResult `json:"results"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, res := range body.Results {
		status := "done"
		if !res.OK {
			status = "error"
		}
		// bound to machine_id so an agent can only ack its OWN commands
		_, _ = s.db.Exec(`UPDATE fleet_commands SET status=?, result=?, done_at=? WHERE id=? AND machine_id=?`,
			status, res.Output, now, res.ID, m.ID)
	}
	s.broadcastCommands(m.ID) // push done/error status to a watching detail page
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
