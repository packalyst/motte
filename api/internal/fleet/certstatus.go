package fleet

import (
	"crypto/x509"
	"database/sql"
	"time"
)

// What the Certificates page and the expiry check read from the fleet: the CA, the listener's own
// certificate and each enrolled machine's client certificate.

// CertInfo describes one certificate.
type CertInfo struct {
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprint"`
	Hosts       []string  `json:"hosts,omitempty"` // the names and IPs it's valid for (listener)
}

// AgentCert is an enrolled machine's current client certificate.
type AgentCert struct {
	MachineID string     `json:"machineId"`
	Name      string     `json:"name"`
	NotAfter  time.Time  `json:"notAfter"`
	LastSeen  *time.Time `json:"lastSeen,omitempty"`
}

// CertStatus is the fleet's certificates. Listener is nil while the agent listener is off; Previous
// and OnOldCA are set during a CA rotation.
type CertStatus struct {
	CA                CertInfo     `json:"ca"`
	Previous          *CertInfo    `json:"previous"` // the CA being replaced
	OnOldCA           []MachineRef `json:"onOldCA"`  // machines that haven't moved to the new CA yet
	Listener          *CertInfo    `json:"listener"`
	Agents            []AgentCert  `json:"agents"`
	AgentLifetimeDays int          `json:"agentLifetimeDays"` // what a new or renewed client cert lasts
}

func certInfo(c *x509.Certificate, hosts []string) CertInfo {
	return CertInfo{NotBefore: c.NotBefore, NotAfter: c.NotAfter, Fingerprint: fingerprintFromCert(c), Hosts: hosts}
}

// CertStatus collects the fleet's certificates, soonest-expiring machine first.
func (s *Service) CertStatus() (CertStatus, error) {
	set := s.cas.Load()
	st := CertStatus{CA: certInfo(set.active.cert, nil), Agents: []AgentCert{}, AgentLifetimeDays: int(s.clientCertTTL() / (24 * time.Hour))}
	if set.rotating() {
		prev := certInfo(set.prev.cert, nil)
		st.Previous = &prev
		var err error
		if st.OnOldCA, err = s.machinesOnOldCA(); err != nil {
			return st, err
		}
	}
	if on, _ := s.Status(); on {
		if c, hosts := s.currentListenerCert(); c != nil {
			li := certInfo(c.Leaf, hosts)
			st.Listener = &li
		}
	}
	rows, err := s.db.Query(`SELECT id, name, cert_expires, last_seen FROM fleet_machines
		WHERE revoked = 0 AND cert_expires IS NOT NULL ORDER BY cert_expires`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var a AgentCert
		var expires, seen sql.NullString
		if err := rows.Scan(&a.MachineID, &a.Name, &expires, &seen); err != nil {
			return st, err
		}
		t := parseTimePtr(expires)
		if t == nil {
			continue
		}
		a.NotAfter, a.LastSeen = *t, parseTimePtr(seen)
		st.Agents = append(st.Agents, a)
	}
	return st, rows.Err()
}
