package fleet

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// Replacing the fleet CA (for its expiry, or a leaked key) without cutting machines off.
//
// The existing CA signs leaves only (path length 0), so agents can't reach the panel through a chain
// from a new CA. A replacement therefore runs in two phases:
//
//   - Rotation: a new CA is made. The old one stays the panel's face (the listener certificate, the
//     install pin, new enrollments), so every agent keeps connecting. The new one issues renewals.
//     Agents learn it from /trust, vouched for by the old CA (a cross-signed copy), and an agent
//     whose certificate isn't from it renews right away; the panel accepts that during a rotation.
//   - Finish: once every machine holds a certificate from the new CA (it verified that certificate
//     against the new CA, so it trusts it), the old CA is dropped and the new one becomes the face.
//     Finishing early ("force") cuts off the machines still on the old CA: they must be re-enrolled.

// caSet is the panel's CAs.
type caSet struct {
	active *CA               // issues renewals; outside a rotation, the only CA
	prev   *CA               // during a rotation: the CA being replaced, still the panel's face
	cross  *x509.Certificate // during a rotation: active's name and key signed by prev
}

func (c *caSet) rotating() bool { return c.prev != nil }

// serving is the CA the panel presents itself with: its listener certificate, the install pin, and
// the CA new enrollments get.
func (c *caSet) serving() *CA {
	if c.prev != nil {
		return c.prev
	}
	return c.active
}

// pool holds every CA whose client certificates are accepted.
func (c *caSet) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.active.cert)
	if c.prev != nil {
		p.AddCert(c.prev.cert)
	}
	return p
}

// issuedBy reports whether cert was signed by ca.
func issuedBy(cert *x509.Certificate, ca *CA) bool {
	return bytes.Equal(cert.AuthorityKeyId, ca.cert.SubjectKeyId) && cert.CheckSignatureFrom(ca.cert) == nil
}

// loadCASet reads the CAs, making the first one on a new panel.
func loadCASet(db *sql.DB) (*caSet, error) {
	rows, err := db.Query(`SELECT id, cert_pem, key_enc, state, COALESCE(cross_pem, '') FROM fleet_ca ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := &caSet{}
	var crossPEM string
	for rows.Next() {
		var id int64
		var certPEM, keyEnc, state, xPEM string
		if err := rows.Scan(&id, &certPEM, &keyEnc, &state, &xPEM); err != nil {
			return nil, err
		}
		ca, err := parseCA(certPEM, keyEnc)
		if err != nil {
			return nil, err
		}
		ca.id = id
		switch {
		case state == "active" && set.active == nil:
			set.active, crossPEM = ca, xPEM
		case state == "previous" && set.prev == nil:
			set.prev = ca
		default:
			return nil, fmt.Errorf("fleet CA: unexpected %q CA (row %d)", state, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if set.active == nil && set.prev == nil {
		ca, keyEnc, err := newCA("motte-panel-ca")
		if err != nil {
			return nil, err
		}
		if err := insertCA(db, ca, keyEnc, "active", ""); err != nil {
			return nil, err
		}
		return &caSet{active: ca}, nil
	}
	if set.active == nil {
		return nil, errors.New("fleet CA: no active CA")
	}
	if set.prev != nil {
		b, _ := pem.Decode([]byte(crossPEM))
		if b == nil {
			return nil, errors.New("fleet CA: rotation without its cross-signed certificate")
		}
		if set.cross, err = x509.ParseCertificate(b.Bytes); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// crossSign signs next's name and key with by: the proof agents trusting by accept next on.
func crossSign(next, by *CA) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := next.cert.NotAfter
	if by.cert.NotAfter.Before(notAfter) {
		notAfter = by.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            next.cert.RawSubject,
		SubjectKeyId:          next.cert.SubjectKeyId,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, by.cert, next.cert.PublicKey, by.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

var (
	errRotating    = errors.New("a CA replacement is already in progress: finish it first")
	errNotRotating = errors.New("no CA replacement is in progress")
	errNotMoved    = errors.New("some machines still have a certificate from the old CA")
)

// RotateCA starts replacing the CA: a new one issues renewals from now on, while the current one
// stays the panel's face until FinishCARotation.
func (s *Service) RotateCA() error {
	s.caMu.Lock()
	defer s.caMu.Unlock()
	cur := s.cas.Load()
	if cur.rotating() {
		return errRotating
	}
	next, keyEnc, err := newCA("motte-panel-ca " + time.Now().UTC().Format(time.DateOnly))
	if err != nil {
		return err
	}
	cross, err := crossSign(next, cur.active)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE fleet_ca SET state = 'previous' WHERE id = ?`, cur.active.id); err != nil {
		return err
	}
	if err := insertCA(tx, next, keyEnc, "active", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cross.Raw}))); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.cas.Store(&caSet{active: next, prev: cur.active, cross: cross})
	return nil
}

// minTrustAgent is the first agent release that learns a new CA and moves to it by itself.
const minTrustAgent = "0.1.67"

// MachineRef names a machine still on the old CA, and whether its agent is too old to move by itself.
type MachineRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	OldAgent bool   `json:"oldAgent"` // needs an agent update (or re-enroll) first
}

// machinesOnOldCA lists the enrolled machines whose certificate isn't from the active CA yet.
func (s *Service) machinesOnOldCA() ([]MachineRef, error) {
	rows, err := s.db.Query(`SELECT id, name, COALESCE(last_report, '') FROM fleet_machines WHERE revoked = 0 AND COALESCE(cert_ca, '') <> ? ORDER BY name`,
		s.cas.Load().active.Fingerprint())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MachineRef{}
	for rows.Next() {
		var m MachineRef
		var report string
		if err := rows.Scan(&m.ID, &m.Name, &report); err != nil {
			return nil, err
		}
		agent := ""
		if sum := summarize(report); sum != nil {
			agent = sum.Agent
		}
		m.OldAgent = !releaseAtLeast(agent, minTrustAgent)
		out = append(out, m)
	}
	return out, rows.Err()
}

// FinishCARotation drops the old CA and makes the new one the panel's face (the listener certificate
// follows on the next handshake). Unless force, it refuses while any machine is still on the old CA;
// it returns those machines. Forced, they're cut off: their live link and console are closed, and
// their certificate no longer passes the handshake.
func (s *Service) FinishCARotation(force bool) ([]MachineRef, error) {
	s.caMu.Lock()
	defer s.caMu.Unlock()
	cur := s.cas.Load()
	if !cur.rotating() {
		return nil, errNotRotating
	}
	left, err := s.machinesOnOldCA()
	if err != nil {
		return nil, err
	}
	if len(left) > 0 && !force {
		return left, errNotMoved
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM fleet_ca WHERE id = ?`, cur.prev.id); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE fleet_ca SET cross_pem = NULL WHERE id = ?`, cur.active.id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.cas.Store(&caSet{active: cur.active})
	for _, m := range left {
		consoleTeardown(m.ID)
		linkTeardown(m.ID)
	}
	return left, nil
}

type caStepRequest struct {
	Force           bool   `json:"force"`
	CurrentPassword string `json:"currentPassword"`
	TotpCode        string `json:"totpCode"`
}

// decodeCAStep reads a CA step's request and requires a fresh step-up (every time, like deleting a
// machine). Returns false after answering.
func (s *Service) decodeCAStep(w http.ResponseWriter, r *http.Request) (caStepRequest, bool) {
	var req caStepRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		router.JSONError(w, "invalid request", http.StatusBadRequest)
		return req, false
	}
	if status, err := s.consoleStepUp(r, req.CurrentPassword, req.TotpCode); err != nil {
		router.JSONError(w, err.Error(), status)
		return req, false
	}
	return req, true
}

// handleRotateCA (POST /api/fleet/ca/rotate, admin) starts replacing the CA.
func (s *Service) handleRotateCA(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.decodeCAStep(w, r); !ok {
		return
	}
	if err := s.RotateCA(); err != nil {
		if errors.Is(err, errRotating) {
			router.JSONError(w, err.Error(), http.StatusConflict)
			return
		}
		log.Printf("fleet: CA rotation: %v", err)
		router.JSONError(w, "could not create the new CA", http.StatusInternalServerError)
		return
	}
	actor, _ := s.actingAdmin(r)
	events.Audit("fleet", "ca_rotation_started", events.SeverityWarning, actor, helper.GetClientIP(r),
		fmt.Sprintf("Fleet CA replacement started: new CA %s issues renewals; machines move to it as they connect", s.cas.Load().active.Fingerprint()))
	router.JSON(w, map[string]bool{"ok": true})
}

// handleFinishCARotation (POST /api/fleet/ca/finish {"force"}, admin) makes the new CA the only one.
// Without force it answers 409 with the machines still on the old CA.
func (s *Service) handleFinishCARotation(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeCAStep(w, r)
	if !ok {
		return
	}
	left, err := s.FinishCARotation(req.Force)
	switch {
	case errors.Is(err, errNotMoved):
		router.JSONWithStatus(w, map[string]any{"error": err.Error(), "machines": left}, http.StatusConflict)
		return
	case errors.Is(err, errNotRotating):
		router.JSONError(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		log.Printf("fleet: finishing the CA rotation: %v", err)
		router.JSONError(w, "could not finish the CA replacement", http.StatusInternalServerError)
		return
	}
	actor, _ := s.actingAdmin(r)
	msg, sev := "Fleet CA replacement finished: the old CA is no longer trusted", events.SeverityWarning
	if len(left) > 0 {
		names := make([]string, len(left))
		for i, m := range left {
			names[i] = m.Name
		}
		msg, sev = fmt.Sprintf("Fleet CA replacement finished early: %d machine(s) cut off and must be re-enrolled: %s", len(left), strings.Join(names, ", ")), events.SeverityCritical
	}
	events.Audit("fleet", "ca_rotation_finished", sev, actor, helper.GetClientIP(r), msg)
	router.JSON(w, map[string]any{"ok": true, "cutOff": left})
}
