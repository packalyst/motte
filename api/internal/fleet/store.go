package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"time"
)

// Machine is one enrolled agent.
type Machine struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	MachineHash string     `json:"machine_hash"`
	CertFP      string     `json:"cert_fp"`
	WGPubkey    string     `json:"wg_pubkey,omitempty"`
	Status      string     `json:"status"`
	EnrolledAt  time.Time  `json:"enrolled_at"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	Revoked     bool       `json:"revoked"`
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

// machineIdentityHash binds a machine to its /etc/machine-id (+ WG pubkey), so a
// stolen cert+key replayed on a different host can be detected.
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

// ListMachines returns all enrolled machines, newest first.
func (s *Service) ListMachines() ([]Machine, error) {
	rows, err := s.db.Query(`SELECT id, name, machine_hash, cert_fp, wg_pubkey, status, enrolled_at, last_seen, revoked
		FROM fleet_machines ORDER BY enrolled_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Machine{}
	for rows.Next() {
		var m Machine
		var enrolled, lastSeen, wg sql.NullString
		if err := rows.Scan(&m.ID, &m.Name, &m.MachineHash, &m.CertFP, &wg, &m.Status, &enrolled, &lastSeen, &m.Revoked); err != nil {
			return nil, err
		}
		m.WGPubkey = wg.String
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
