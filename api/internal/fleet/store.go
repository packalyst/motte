package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"
)

// Machine is one enrolled agent.
type Machine struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	MachineHash string          `json:"machine_hash"`
	CertFP      string          `json:"cert_fp"`
	WGPubkey    string          `json:"wg_pubkey,omitempty"`
	Status      string          `json:"status"`
	EnrolledAt  time.Time       `json:"enrolled_at"`
	LastSeen    *time.Time      `json:"last_seen,omitempty"`
	Revoked     bool            `json:"revoked"`
	Summary     *MachineSummary `json:"summary,omitempty"`
}

// MachineSummary is the at-a-glance slice of a machine's latest report, so the fleet
// list can render usage bars + threat chips per card without fetching every full report.
type MachineSummary struct {
	CPU         float64 `json:"cpu"`
	Mem         float64 `json:"mem"`
	Disk        float64 `json:"disk"`
	OS          string  `json:"os,omitempty"`
	CVETotal    int     `json:"cve_total"`
	CVECritical int     `json:"cve_critical"`
	Bans        int     `json:"bans"`
	Blocked     int     `json:"blocked"`
	FIM         int     `json:"fim"`
	Agent       string  `json:"agent,omitempty"`
}

// summarize extracts the card-level summary from a raw report JSON document. It reads
// only the handful of fields the fleet list shows; anything missing stays zero.
func summarize(raw string) *MachineSummary {
	if raw == "" || raw == "null" {
		return nil
	}
	var r struct {
		Agent   string `json:"agent"`
		Metrics struct {
			CPU  float64 `json:"cpu"`
			Mem  float64 `json:"mem"`
			Disk float64 `json:"disk"`
		} `json:"metrics"`
		Blocked   []string `json:"blocked"`
		Intrusion struct {
			ActiveBans int `json:"active_bans"`
		} `json:"intrusion"`
		CVEs struct {
			Total  int            `json:"total"`
			Counts map[string]int `json:"counts"`
		} `json:"cves"`
		Facts struct {
			OS  map[string]string `json:"os"`
			FIM []any             `json:"fim"`
		} `json:"facts"`
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil
	}
	s := &MachineSummary{
		CPU: r.Metrics.CPU, Mem: r.Metrics.Mem, Disk: r.Metrics.Disk,
		CVETotal: r.CVEs.Total, CVECritical: r.CVEs.Counts["CRITICAL"],
		Bans: r.Intrusion.ActiveBans, Blocked: len(r.Blocked), FIM: len(r.Facts.FIM),
		Agent: r.Agent,
	}
	if name := r.Facts.OS["name"]; name != "" {
		s.OS = strings.TrimSpace(name + " " + r.Facts.OS["version"])
	}
	return s
}

// DeleteMachine removes a machine and everything tied to it: the registry row (which
// invalidates its client cert, since mTLS auth requires a live, non-revoked cert_fp
// lookup) and any queued commands. A hard delete — the enrolled agent can no longer
// authenticate and must re-enroll with a fresh token to return.
func (s *Service) DeleteMachine(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// Clear everything tied to the machine: its queued commands and its stored CVE rows.
	// (The client cert isn't stored on the panel — only its fingerprint in the row below —
	// so removing the row invalidates it. Tokens are one-time and already consumed.)
	for _, q := range []string{
		`DELETE FROM fleet_commands WHERE machine_id = ?`,
		`DELETE FROM fleet_cves WHERE machine_id = ?`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	res, err := tx.Exec(`DELETE FROM fleet_machines WHERE id = ?`, id)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// MarkUninstalled flags a machine as uninstalled — its agent deregistered on the way
// out — so the panel shows it as gone (list-only, delete to remove) rather than just
// "offline". Keeps the row so the operator can see + delete it deliberately.
func (s *Service) MarkUninstalled(id string) error {
	_, err := s.db.Exec(`UPDATE fleet_machines SET status='uninstalled', last_seen=? WHERE id=?`,
		time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func newMachineID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// certFingerprintPEM returns "sha256:<hex>" of the DER inside a cert PEM.
func certFingerprintPEM(certPEM []byte) string {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// machineIdentityHash records a stable fingerprint of the host identity
// (/etc/machine-id + WG pubkey) captured AT ENROLL. The enforced runtime binding is
// the client-cert fingerprint (see requireClientCert); this hash is the provenance
// anchor for detecting a same-host re-enroll and the intended second factor for a
// future report-time replay check (agent would resend machine-id to compare) — it is
// NOT yet consulted on report, so don't treat it as live replay protection today.
func machineIdentityHash(machineID, wgPubkey string) string {
	sum := sha256.Sum256([]byte(machineID + "|" + wgPubkey))
	return hex.EncodeToString(sum[:])
}

func (s *Service) registerMachine(m Machine) error {
	_, err := s.db.Exec(
		`INSERT INTO fleet_machines (id, name, machine_hash, cert_fp, wg_pubkey, status, enrolled_at, revoked)
		 VALUES (?, ?, ?, ?, ?, 'enrolled', ?, 0)`,
		m.ID, m.Name, m.MachineHash, m.CertFP, m.WGPubkey, m.EnrolledAt.UTC().Format(time.RFC3339),
	)
	return err
}

// ListMachines returns all enrolled machines, newest first, each with an at-a-glance
// summary parsed from its latest report (for the fleet card grid).
func (s *Service) ListMachines() ([]Machine, error) {
	rows, err := s.db.Query(`SELECT id, name, machine_hash, cert_fp, wg_pubkey, status, enrolled_at, last_seen, revoked, last_report
		FROM fleet_machines ORDER BY enrolled_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Machine{}
	for rows.Next() {
		var m Machine
		var enrolled, lastSeen, wg, report sql.NullString
		if err := rows.Scan(&m.ID, &m.Name, &m.MachineHash, &m.CertFP, &wg, &m.Status, &enrolled, &lastSeen, &m.Revoked, &report); err != nil {
			return nil, err
		}
		m.WGPubkey = wg.String
		m.Summary = summarize(report.String)
		if enrolled.Valid {
			m.EnrolledAt, _ = time.Parse(time.RFC3339, enrolled.String)
		}
		if lastSeen.Valid && lastSeen.String != "" {
			t, _ := time.Parse(time.RFC3339, lastSeen.String)
			m.LastSeen = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// machineByCertFP looks up a non-revoked machine by its client cert fingerprint
// (used by the mTLS layer to authorize an agent). Returns nil if none/revoked.
func (s *Service) machineByCertFP(fp string) (*Machine, error) {
	var m Machine
	var enrolled sql.NullString
	err := s.db.QueryRow(
		`SELECT id, name, cert_fp, status, enrolled_at, revoked FROM fleet_machines WHERE cert_fp = ? AND revoked = 0`, fp,
	).Scan(&m.ID, &m.Name, &m.CertFP, &m.Status, &enrolled, &m.Revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if enrolled.Valid {
		m.EnrolledAt, _ = time.Parse(time.RFC3339, enrolled.String)
	}
	return &m, nil
}

// fingerprintFromCert returns "sha256:<hex>" for a parsed certificate.
func fingerprintFromCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// lastReport returns a machine's latest stored report JSON (or "" if none).
func (s *Service) lastReport(id string) (string, error) {
	var raw sql.NullString
	if err := s.db.QueryRow(`SELECT last_report FROM fleet_machines WHERE id = ?`, id).Scan(&raw); err != nil {
		return "", err
	}
	return raw.String, nil
}
