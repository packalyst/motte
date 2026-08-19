package fleet

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// allowedCommands is the ONLY set of actions the panel can tell an agent to run.
// Never a shell string. The agent independently re-checks this set before acting,
// so a compromised panel row still can't make the agent run arbitrary code.
var allowedCommands = map[string]bool{
	"block":         true,
	"unblock":       true,
	"apply-updates": true,
	"restart":       true,
	"rescan":        true, // re-run the Trivy CVE scan now (don't wait for the interval)
	"sync-blocks":   true, // push the panel's explicit blocklist onto this machine
	"fix-packages":  true, // targeted OS-package upgrades for selected CVEs
	"set-dry-run":   true, // flip enforcement on/off (dry-run) live
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

// Enqueue adds an allowlisted command for a machine.
func (s *Service) Enqueue(machineID, ctype string, payload json.RawMessage) (string, error) {
	if !allowedCommands[ctype] {
		return "", fmt.Errorf("command %q not allowed", ctype)
	}
	id := newCommandID()
	_, err := s.db.Exec(
		`INSERT INTO fleet_commands (id, machine_id, type, payload, status, created_at) VALUES (?,?,?,?, 'pending', ?)`,
		id, machineID, ctype, string(payload), time.Now().UTC().Format(time.RFC3339),
	)
	return id, err
}

// MachineCommand is one queued command with its lifecycle, for the admin command log.
type MachineCommand struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Status    string `json:"status"` // pending | delivered | done | error
	Result    string `json:"result,omitempty"`
	CreatedAt string `json:"created_at"`
	DoneAt    string `json:"done_at,omitempty"`
}

// ListMachineCommands returns a machine's most recent commands (newest first).
func (s *Service) ListMachineCommands(machineID string, limit int) ([]MachineCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT id, type, status, result, created_at, done_at FROM fleet_commands
		 WHERE machine_id = ? ORDER BY created_at DESC LIMIT ?`, machineID, limit)
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

// handleMachineCommands (GET /api/fleet/machine/commands?machine_id=) — the command log.
func (s *Service) handleMachineCommands(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("machine_id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "machine_id required")
		return
	}
	cmds, err := s.ListMachineCommands(id, 20)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, cmds)
}

// HandleCommands (GET, mTLS) returns this machine's pending commands and marks
// them delivered. The machine comes from the client cert.
func (s *Service) HandleCommands(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	rows, err := s.db.Query(
		`SELECT id, type, payload FROM fleet_commands WHERE machine_id = ? AND status = 'pending' ORDER BY created_at`, m.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	cmds := []Command{}
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
	}
	if len(cmds) > 0 {
		_, _ = s.db.Exec(`UPDATE fleet_commands SET status='delivered', delivered_at=? WHERE machine_id=? AND status='pending'`,
			time.Now().UTC().Format(time.RFC3339), m.ID)
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
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
