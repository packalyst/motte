package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"strings"
	"time"

	"api/internal/helper"
)

// Machine is one enrolled agent.
type Machine struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	MachineHash    string          `json:"machine_hash"`
	CertFP         string          `json:"cert_fp"`
	WGPubkey       string          `json:"wg_pubkey,omitempty"`
	Status         string          `json:"status"`
	EnrolledAt     time.Time       `json:"enrolled_at"`
	LastSeen       *time.Time      `json:"last_seen,omitempty"`
	Revoked        bool            `json:"revoked"`
	Tags           []string        `json:"tags"`
	ConsoleEnabled bool            `json:"console_enabled"`
	ConsoleRecord  bool            `json:"console_record"`
	LastIP         string          `json:"last_ip,omitempty"` // address its last report came from (matches a VPN client when it reports over the tunnel)
	Online         bool            `json:"online"`            // its link to the panel is up (see link.go)
	CertExpires    *time.Time      `json:"cert_expires,omitempty"`
	Summary        *MachineSummary `json:"summary,omitempty"`
}

// splitTags parses the stored CSV tag list into a trimmed, non-empty slice.
func splitTags(csv string) []string {
	out := []string{}
	for _, t := range strings.Split(csv, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
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
			OS map[string]string `json:"os"`
			// FIM events ride a separate /fim-report; the periodic report carries only the count.
			FIMCount int `json:"fim_count"`
		} `json:"facts"`
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil
	}
	s := &MachineSummary{
		CPU: r.Metrics.CPU, Mem: r.Metrics.Mem, Disk: r.Metrics.Disk,
		CVETotal: r.CVEs.Total, CVECritical: r.CVEs.Counts["CRITICAL"],
		Bans: r.Intrusion.ActiveBans, Blocked: len(r.Blocked), FIM: r.Facts.FIMCount,
		Agent: r.Agent,
	}
	if name := r.Facts.OS["name"]; name != "" {
		s.OS = strings.TrimSpace(name + " " + r.Facts.OS["version"])
	}
	return s
}

// machineDataTables hold per-machine data, removed with the machine (and swept for orphans at boot).
var machineDataTables = []string{"fleet_commands", "fleet_cves", "fleet_scans", "fleet_fim", "fleet_metrics"}

// purgeMachineData deletes a machine's stored data inside tx: queued commands, vulnerabilities,
// scan history, file-integrity events and usage history. Table names are compile-time constants.
func purgeMachineData(tx *sql.Tx, id string) error {
	for _, tbl := range machineDataTables {
		if _, err := tx.Exec(`DELETE FROM `+tbl+` WHERE machine_id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

// withMachineTx runs fn in a transaction, then closes the machine's live channels and deletes its
// console recordings. Used by delete and uninstall, which both end the machine's data.
func (s *Service) withMachineTx(id string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	consoleTeardown(id) // drop any live console channel/sessions (and close open recordings) first
	linkTeardown(id)
	purgeRecordings(id)
	return nil
}

// DeleteMachine removes a machine and everything tied to it. Removing the row invalidates its
// client cert (mTLS auth needs a live cert_fp lookup; the panel never stores the cert itself), so
// the agent must re-enroll with a fresh token to return.
func (s *Service) DeleteMachine(id string) error {
	return s.withMachineTx(id, func(tx *sql.Tx) error {
		if err := purgeMachineData(tx, id); err != nil {
			return err
		}
		res, err := tx.Exec(`DELETE FROM fleet_machines WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

// MarkUninstalled handles an agent deregistering on its way out: its cert stops working at once
// (revoked), and all its data is deleted. Only a marker stays — name, when it was added and when it
// was uninstalled (last_seen) — so the operator sees it happened until they remove it. Reinstalling
// enrolls a fresh machine.
func (s *Service) MarkUninstalled(id string) error {
	return s.withMachineTx(id, func(tx *sql.Tx) error {
		if err := purgeMachineData(tx, id); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE fleet_machines SET status='uninstalled', revoked=1, last_seen=?,
			last_report=NULL, tags='', last_ip='', wg_pubkey='', machine_hash='', console_enabled=0, console_record=0,
			cert_expires=NULL, cert_fp_next=NULL, cert_expires_next=NULL WHERE id=?`,
			time.Now().UTC().Format(time.RFC3339), id)
		return err
	})
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

// uniqueMachineName returns name, or name-2, name-3 … when an active (not revoked) machine already
// uses it (case-insensitive), so two hosts with the same hostname stay tell-apart-able everywhere.
// The result stays within the 64-character name limit.
func (s *Service) uniqueMachineName(name string) string {
	rows, err := s.db.Query(`SELECT LOWER(name) FROM fleet_machines WHERE revoked = 0`)
	if err != nil {
		return name
	}
	taken := map[string]bool{}
	for rows.Next() {
		var n sql.NullString
		if rows.Scan(&n) == nil {
			taken[n.String] = true
		}
	}
	rows.Close()
	if !taken[strings.ToLower(name)] {
		return name
	}
	for i := 2; ; i++ {
		suffix := "-" + strconv.Itoa(i)
		base := name
		if len(base)+len(suffix) > 64 {
			base = strings.TrimSpace(base[:64-len(suffix)])
		}
		if c := base + suffix; !taken[strings.ToLower(c)] {
			return c
		}
	}
}

func (s *Service) registerMachine(m Machine) error {
	_, err := s.db.Exec(
		`INSERT INTO fleet_machines (id, name, machine_hash, cert_fp, wg_pubkey, status, enrolled_at, revoked, cert_expires)
		 VALUES (?, ?, ?, ?, ?, 'enrolled', ?, 0, ?)`,
		m.ID, m.Name, m.MachineHash, m.CertFP, m.WGPubkey, m.EnrolledAt.UTC().Format(time.RFC3339), timeOrNil(m.CertExpires),
	)
	return err
}

// ListMachines returns all enrolled machines, newest first, each with an at-a-glance
// summary parsed from its latest report (for the fleet card grid).
func (s *Service) ListMachines() ([]Machine, error) {
	rows, err := s.db.Query(`SELECT id, name, machine_hash, cert_fp, wg_pubkey, status, enrolled_at, last_seen, revoked, last_report, COALESCE(tags, ''), COALESCE(console_enabled, 0), COALESCE(console_record, 0), COALESCE(last_ip, ''), cert_expires
		FROM fleet_machines ORDER BY enrolled_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Machine{}
	for rows.Next() {
		var m Machine
		var enrolled, lastSeen, wg, report, tags, certExpires sql.NullString
		var consoleEnabled, consoleRecord int
		if err := rows.Scan(&m.ID, &m.Name, &m.MachineHash, &m.CertFP, &wg, &m.Status, &enrolled, &lastSeen, &m.Revoked, &report, &tags, &consoleEnabled, &consoleRecord, &m.LastIP, &certExpires); err != nil {
			return nil, err
		}
		m.CertExpires = parseTimePtr(certExpires)
		m.WGPubkey = wg.String
		m.Tags = splitTags(tags.String)
		m.ConsoleEnabled = consoleEnabled == 1
		m.ConsoleRecord = consoleRecord == 1
		m.Summary = summarize(report.String)
		m.Online = !m.Revoked && linkOnline(m.ID)
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

// machineByCertFP looks up a non-revoked machine by its client cert fingerprint — its current cert
// or the renewed one it hasn't switched to yet (renew.go). Used by the mTLS layer to authorize an
// agent. Returns nil if none/revoked.
func (s *Service) machineByCertFP(fp string) (*Machine, error) {
	var m Machine
	var enrolled, certExpires sql.NullString
	err := s.db.QueryRow(
		`SELECT id, name, cert_fp, status, enrolled_at, revoked, cert_expires FROM fleet_machines
		 WHERE (cert_fp = ? OR cert_fp_next = ?) AND revoked = 0`, fp, fp,
	).Scan(&m.ID, &m.Name, &m.CertFP, &m.Status, &enrolled, &m.Revoked, &certExpires)
	m.CertExpires = parseTimePtr(certExpires)
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

// machineByID loads one non-revoked machine with the fields the console path needs (tags for
// scope, console flags). Returns nil if unknown or revoked.
func (s *Service) machineByID(id string) (*Machine, error) {
	var m Machine
	var tags sql.NullString
	var consoleEnabled, consoleRecord int
	err := s.db.QueryRow(
		`SELECT id, name, COALESCE(tags, ''), COALESCE(console_enabled, 0), COALESCE(console_record, 0) FROM fleet_machines WHERE id = ? AND revoked = 0`, id,
	).Scan(&m.ID, &m.Name, &tags, &consoleEnabled, &consoleRecord)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.Tags = splitTags(tags.String)
	m.ConsoleEnabled = consoleEnabled == 1
	m.ConsoleRecord = consoleRecord == 1
	return &m, nil
}

// setConsoleEnabled flips a machine's console gate (and optionally recording).
func (s *Service) setConsoleEnabled(id string, enabled, record bool) error {
	_, err := s.db.Exec(`UPDATE fleet_machines SET console_enabled = ?, console_record = ? WHERE id = ?`,
		b2i(enabled), b2i(record), id)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// fingerprintFromCert returns "sha256:<hex>" for a parsed certificate.
func fingerprintFromCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// machineTags returns a machine's tags (empty if none/unknown).
func (s *Service) machineTags(id string) ([]string, error) {
	var tags sql.NullString
	if err := s.db.QueryRow(`SELECT COALESCE(tags, '') FROM fleet_machines WHERE id = ?`, id).Scan(&tags); err != nil {
		return nil, err
	}
	return splitTags(tags.String), nil
}

// SetMachineTags replaces a machine's tag set (normalized, de-duplicated CSV).
func (s *Service) SetMachineTags(id string, tags []string) error {
	tags, err := helper.NormalizeTags(tags, "") // also keeps commas out of the stored CSV
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE fleet_machines SET tags = ? WHERE id = ?`, strings.Join(tags, ","), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// lastReport returns a machine's latest stored report JSON (or "" if none).
func (s *Service) lastReport(id string) (string, error) {
	var raw sql.NullString
	if err := s.db.QueryRow(`SELECT last_report FROM fleet_machines WHERE id = ?`, id).Scan(&raw); err != nil {
		return "", err
	}
	return raw.String, nil
}
