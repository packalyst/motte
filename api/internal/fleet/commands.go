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
