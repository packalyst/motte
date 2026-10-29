package fleet

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// enrolledMachine enrolls a machine through /enroll and returns its id and certificate.
func enrolledMachine(t *testing.T, svc *Service) (string, *x509.Certificate) {
	t.Helper()
	tok, err := svc.CreateToken("m", time.Hour, "", "")
	if err != nil {
		t.Fatal(err)
	}
	rr := enrollWith(t, svc, tok.Plaintext)
	if rr.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", rr.Code, rr.Body)
	}
	var resp enrollResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	b, _ := pem.Decode([]byte(resp.ClientCert))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return resp.MachineID, c
}

func certCA(t *testing.T, svc *Service, id string) string {
	t.Helper()
	var fp string
	_ = svc.db.QueryRow(`SELECT COALESCE(cert_ca, '') FROM fleet_machines WHERE id = ?`, id).Scan(&fp)
	return fp
}

func trustOf(t *testing.T, svc *Service) trustResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	svc.HandleTrust(rr, httptest.NewRequest(http.MethodGet, "/trust", nil))
	var tr trustResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &tr)
	return tr
}

func parsePEM(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatal("no PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// verifiesWith reports whether cert passes a client-cert handshake check against pool.
func verifiesWith(cert *x509.Certificate, pool *x509.CertPool) bool {
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err == nil
}

// The whole replacement: the old CA stays the panel's face while machines move to the new one by
// renewing, finishing waits for every machine, then the new CA is the only one.
func TestCARotation(t *testing.T) {
	svc := newTestService(t)
	id, oldCert := enrolledMachine(t, svc)
	old := svc.CA()
	if certCA(t, svc, id) != old.Fingerprint() {
		t.Fatal("enrollment didn't record the issuing CA")
	}

	if err := svc.RotateCA(); err != nil {
		t.Fatal(err)
	}
	if err := svc.RotateCA(); !errors.Is(err, errRotating) {
		t.Fatalf("second rotation: %v", err)
	}
	set := svc.cas.Load()
	next := set.active
	if svc.CA() != old || next == old {
		t.Fatal("during a rotation the panel must still present the old CA")
	}
	if lc, err := svc.serverCertificate(nil); err != nil || !issuedBy(lc.Leaf, old) {
		t.Fatalf("listener certificate must stay on the old CA: %v", err)
	}
	if !verifiesWith(oldCert, set.pool()) {
		t.Fatal("certificates from the old CA must keep working during a rotation")
	}

	// /trust lists both CAs and proves the new one the way the agent checks it.
	tr := trustOf(t, svc)
	if len(tr.CAs) != 2 || len(tr.Cross) != 1 || tr.Issuer != next.Fingerprint() {
		t.Fatalf("trust: %d CAs, %d cross, issuer %s", len(tr.CAs), len(tr.Cross), tr.Issuer)
	}
	x, nc := parsePEM(t, tr.Cross[0]), parsePEM(t, tr.CAs[1])
	if !bytes.Equal(x.RawSubject, nc.RawSubject) || !bytes.Equal(x.RawSubjectPublicKeyInfo, nc.RawSubjectPublicKeyInfo) ||
		x.CheckSignatureFrom(old.cert) != nil || !x.IsCA || !nc.Equal(next.cert) {
		t.Fatal("the cross-signed copy doesn't vouch for the new CA")
	}

	// A fresh certificate from the old CA may renew at once, and gets one from the new CA.
	_, csr := makeCSR(t, id)
	body, _ := json.Marshal(renewRequest{CSR: string(csr)})
	rr := callAs(svc, svc.HandleRenew, oldCert, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("renewal during rotation: %d %s", rr.Code, rr.Body)
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	renewed := parsePEM(t, resp["client_cert"])
	if !issuedBy(renewed, next) {
		t.Fatal("the renewed certificate isn't from the new CA")
	}

	// Not moved until the machine uses it.
	if left, err := svc.FinishCARotation(false); !errors.Is(err, errNotMoved) || len(left) != 1 || left[0].ID != id || !left[0].OldAgent {
		t.Fatalf("finish before the machine moved: %v %+v", err, left)
	}
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	if rr := callAs(svc, ok, renewed, nil); rr.Code != http.StatusOK {
		t.Fatalf("renewed certificate rejected: %d", rr.Code)
	}
	if certCA(t, svc, id) != next.Fingerprint() {
		t.Fatal("using the renewed certificate didn't move the machine to the new CA")
	}

	left, err := svc.FinishCARotation(false)
	if err != nil || len(left) != 0 {
		t.Fatalf("finish: %v %+v", err, left)
	}
	if svc.CA() != next || svc.cas.Load().rotating() {
		t.Fatal("after finishing, the new CA must be the only one")
	}
	if verifiesWith(oldCert, svc.cas.Load().pool()) {
		t.Fatal("a certificate from the old CA still passes the handshake")
	}
	if lc, err := svc.serverCertificate(nil); err != nil || !issuedBy(lc.Leaf, next) {
		t.Fatalf("the listener certificate didn't move to the new CA: %v", err)
	}
	if tr := trustOf(t, svc); len(tr.CAs) != 1 || len(tr.Cross) != 0 {
		t.Fatalf("trust after finishing: %+v", tr)
	}
	var rows int
	_ = svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_ca`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("%d CA rows after finishing", rows)
	}
	if reloaded, err := loadCASet(svc.db); err != nil || reloaded.rotating() || !reloaded.active.cert.Equal(next.cert) {
		t.Fatalf("reload after finishing: %v", err)
	}
	if _, err := svc.FinishCARotation(false); !errors.Is(err, errNotRotating) {
		t.Fatalf("finish with no rotation: %v", err)
	}
}

// A restart mid-rotation picks it up where it was; machines enrolling meanwhile get the old CA (the
// one their install pins) and are listed as still to move.
func TestCARotationSurvivesRestartAndEnrollment(t *testing.T) {
	svc := newTestService(t)
	if err := svc.RotateCA(); err != nil {
		t.Fatal(err)
	}
	before := svc.cas.Load()
	reloaded, err := loadCASet(svc.db)
	if err != nil || !reloaded.rotating() || !reloaded.prev.cert.Equal(before.prev.cert) ||
		!reloaded.active.cert.Equal(before.active.cert) || !reloaded.cross.Equal(before.cross) {
		t.Fatalf("reload mid-rotation: %v", err)
	}
	id, cert := enrolledMachine(t, svc)
	if !issuedBy(cert, before.prev) || certCA(t, svc, id) != before.prev.Fingerprint() {
		t.Fatal("a machine enrolling during a rotation must get the CA its install pinned")
	}
	if left, _ := svc.machinesOnOldCA(); len(left) != 1 || left[0].ID != id {
		t.Fatalf("on old CA: %+v", left)
	}
}

// Finishing early cuts off the machines still on the old CA.
func TestCARotationForcedFinish(t *testing.T) {
	svc := newTestService(t)
	id, oldCert := enrolledMachine(t, svc)
	if err := svc.RotateCA(); err != nil {
		t.Fatal(err)
	}
	left, err := svc.FinishCARotation(true)
	if err != nil || len(left) != 1 || left[0].ID != id {
		t.Fatalf("forced finish: %v %+v", err, left)
	}
	if verifiesWith(oldCert, svc.cas.Load().pool()) {
		t.Fatal("a cut-off machine's certificate still passes the handshake")
	}
	if hc := svc.handshakeConfig(); !hc.SessionTicketsDisabled || !hc.ClientCAs.Equal(svc.cas.Load().pool()) {
		t.Fatal("the listener must check every client certificate against the current CAs, without resumption")
	}
}

// Machines enrolled before the panel recorded issuing CAs are attributed to the one CA it had.
func TestCertCABackfill(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "legacy", false)
	again, err := New(svc.db, "panel.example", nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if certCA(t, again, "legacy") != again.CA().Fingerprint() {
		t.Fatal("legacy machine not attributed to the CA")
	}
}

// Both CA steps take a fresh password; without one nothing changes.
func TestCAStepsNeedStepUp(t *testing.T) {
	svc := newTestService(t)
	for _, h := range []http.HandlerFunc{svc.handleRotateCA, svc.handleFinishCARotation} {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"force":true}`)))
		if rr.Code != http.StatusPreconditionRequired {
			t.Fatalf("got %d", rr.Code)
		}
	}
	if svc.cas.Load().rotating() {
		t.Fatal("rotated without a step-up")
	}
}
