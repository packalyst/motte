package fleet

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"time"

	"api/internal/events"
	"api/internal/helper"
)

// Client-cert renewal. An agent whose cert is inside renewWindow of expiring asks for a new one over
// its current mTLS identity, with a CSR for a key it just generated. The new cert is held as the
// machine's *next* cert: both work until the agent first connects with the new one, which then
// replaces the old (promoteCert). So a renewal that's interrupted — the agent never saves or uses
// the new cert — can't lock the machine out; it just renews again next time.

// renewWindow: renewal is only accepted this close to expiry, so a stolen-but-valid cert can't be
// used to mint fresh certs indefinitely ahead of time.
const renewWindow = 30 * 24 * time.Hour

type renewRequest struct {
	CSR string `json:"csr"`
}

// HandleRenew (POST /renew, mTLS) signs a fresh client cert for the calling machine.
func (s *Service) HandleRenew(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if m == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		writeErr(w, http.StatusUnauthorized, "no machine")
		return
	}
	if left := time.Until(r.TLS.PeerCertificates[0].NotAfter); left > renewWindow {
		writeErr(w, http.StatusConflict, "certificate is not due for renewal yet")
		return
	}
	var req renewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrollBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		writeErr(w, http.StatusBadRequest, "invalid CSR")
		return
	}
	certPEM, err := s.ca.SignClientCSR(block.Bytes, m.ID, s.clientCertTTL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "csr rejected")
		return
	}
	notAfter, err := certNotAfterPEM(certPEM)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	res, err := s.db.Exec(`UPDATE fleet_machines SET cert_fp_next = ?, cert_expires_next = ? WHERE id = ? AND revoked = 0`,
		certFingerprintPEM(certPEM), notAfter.UTC().Format(time.RFC3339), m.ID)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	events.Audit("fleet", "cert_renewal_issued", events.SeverityInfo, m.Name, helper.GetClientIP(r),
		fmt.Sprintf("Issued a renewed client certificate for machine %s (valid until %s); the current one stays valid until it's first used", m.ID, notAfter.UTC().Format(time.DateOnly)))
	writeJSON(w, http.StatusOK, map[string]string{"client_cert": string(certPEM)})
}

// syncCert runs on every authenticated agent request. A request made with the machine's pending
// next cert promotes it (the old cert stops working); a machine with no recorded expiry gets it
// from the cert it presented.
func (s *Service) syncCert(m *Machine, presented *x509.Certificate, fp string) {
	if fp != m.CertFP { // matched cert_fp_next: the agent switched to its renewed cert
		res, err := s.db.Exec(`UPDATE fleet_machines SET cert_fp = cert_fp_next, cert_expires = cert_expires_next,
			cert_fp_next = NULL, cert_expires_next = NULL WHERE id = ? AND cert_fp_next = ?`, m.ID, fp)
		if n, _ := res.RowsAffected(); err == nil && n == 1 {
			m.CertFP = fp
			log.Printf("fleet: machine %s switched to its renewed certificate", m.ID)
			events.Audit("fleet", "cert_renewed", events.SeverityInfo, m.Name, "",
				fmt.Sprintf("Machine %s now uses its renewed client certificate; the previous one no longer works", m.ID))
		}
		return
	}
	if m.CertExpires == nil {
		_, _ = s.db.Exec(`UPDATE fleet_machines SET cert_expires = ? WHERE id = ? AND cert_expires IS NULL`,
			presented.NotAfter.UTC().Format(time.RFC3339), m.ID)
	}
}

// certNotAfterPEM returns a PEM certificate's expiry.
func certNotAfterPEM(certPEM []byte) (time.Time, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return time.Time{}, fmt.Errorf("not a PEM certificate")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}

// parseTimePtr turns a stored RFC3339 value into a *time.Time (nil when empty or invalid).
func parseTimePtr(v sql.NullString) *time.Time {
	if !v.Valid || v.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, v.String)
	if err != nil {
		return nil
	}
	return &t
}

// timeOrNil stores an optional time as RFC3339, or NULL.
func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}
