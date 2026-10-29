package fleet

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// issueCert signs a client cert for machine id with the given lifetime and parses it.
func issueCert(t *testing.T, svc *Service, id string, ttl time.Duration) (*x509.Certificate, []byte) {
	t.Helper()
	_, csr := makeCSR(t, id)
	b, _ := pem.Decode(csr)
	certPEM, err := svc.CA().SignClientCSR(b.Bytes, id, ttl)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c, certPEM
}

// agedCert signs a client cert for machine id that has lived lifetime-left of its lifetime, so
// left remains: what an agent holds when renewal comes due.
func agedCert(t *testing.T, svc *Service, id string, lifetime, left time.Duration) (*x509.Certificate, []byte) {
	t.Helper()
	key, _ := makeCSR(t, id)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: id},
		NotBefore: now.Add(left - lifetime), NotAfter: now.Add(left), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, svc.CA().cert, &key.PublicKey, svc.CA().key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// callAs runs an mTLS-gated handler as if the agent presented cert.
func callAs(svc *Service, h http.HandlerFunc, cert *x509.Certificate, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/renew", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rr := httptest.NewRecorder()
	svc.requireClientCert(h)(rr, r)
	return rr
}

// Renewal issues a pending cert; the old one keeps working until the new one is first used, which
// then replaces it. A cert far from expiry can't be renewed, and a revoked machine can't renew.
func TestRenewKeepsOldCertUntilNewOneIsUsed(t *testing.T) {
	svc := newTestService(t)
	old, oldPEM := agedCert(t, svc, "m1", 90*24*time.Hour, 20*24*time.Hour) // in the last third of its life
	if err := svc.registerMachine(Machine{ID: "m1", Name: "m1", CertFP: certFingerprintPEM(oldPEM), EnrolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_, csr := makeCSR(t, "m1")
	body, _ := json.Marshal(renewRequest{CSR: string(csr)})

	rr := callAs(svc, svc.HandleRenew, old, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("renew: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	nb, _ := pem.Decode([]byte(resp["client_cert"]))
	renewed, err := x509.ParseCertificate(nb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renewed.Verify(x509.VerifyOptions{Roots: svc.cas.Load().pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil || renewed.Subject.CommonName != "m1" {
		t.Fatalf("renewed cert must chain to the panel CA for the same machine: %v", err)
	}

	// Both work until the new one is used.
	if m, _ := svc.machineByCertFP(fingerprintFromCert(old)); m == nil {
		t.Fatal("the current cert must keep working until the renewed one is used")
	}
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	if rr := callAs(svc, ok, renewed, nil); rr.Code != http.StatusOK {
		t.Fatalf("renewed cert rejected: %d", rr.Code)
	}
	// First use promoted it: the old cert is now refused.
	if rr := callAs(svc, ok, old, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("old cert still accepted after the switch: %d", rr.Code)
	}
	ms, _ := svc.ListMachines()
	if ms[0].CertExpires == nil || ms[0].CertExpires.Sub(renewed.NotAfter).Abs() > time.Second {
		t.Fatalf("expiry not moved to the renewed cert: %v", ms[0].CertExpires)
	}

	// A cert with plenty of life left can't be renewed, however short its lifetime.
	fresh, freshPEM := issueCert(t, svc, "m2", 90*24*time.Hour)
	_ = svc.registerMachine(Machine{ID: "m2", Name: "m2", CertFP: certFingerprintPEM(freshPEM), EnrolledAt: time.Now()})
	if rr := callAs(svc, svc.HandleRenew, fresh, body); rr.Code != http.StatusConflict {
		t.Fatalf("early renewal: %d, want 409", rr.Code)
	}
	short, shortPEM := issueCert(t, svc, "m3", 10*24*time.Hour)
	_ = svc.registerMachine(Machine{ID: "m3", Name: "m3", CertFP: certFingerprintPEM(shortPEM), EnrolledAt: time.Now()})
	if rr := callAs(svc, svc.HandleRenew, short, body); rr.Code != http.StatusConflict {
		t.Fatalf("early renewal of a fresh 10-day cert: %d, want 409", rr.Code)
	}

	// A revoked machine can't renew.
	_, _ = svc.db.Exec(`UPDATE fleet_machines SET revoked = 1 WHERE id = 'm1'`)
	if rr := callAs(svc, svc.HandleRenew, renewed, body); rr.Code != http.StatusUnauthorized {
		t.Fatalf("revoked renewal: %d, want 401", rr.Code)
	}
}

// Renewal opens in the last third of a certificate's own life (plus a day for clock skew).
func TestRenewAllowed(t *testing.T) {
	now := time.Now()
	cert := func(lifetime, left time.Duration) *x509.Certificate {
		return &x509.Certificate{NotBefore: now.Add(left - lifetime), NotAfter: now.Add(left)}
	}
	const day = 24 * time.Hour
	for _, c := range []struct {
		lifetime, left time.Duration
		want           bool
	}{
		{90 * day, 60 * day, false},
		{90 * day, 32 * day, false},
		{90 * day, 30 * day, true},
		{90 * day, 28 * day, true}, // where an older agent asks
		{30 * day, 20 * day, false},
		{30 * day, 10 * day, true},
		{365 * day, 120 * day, true},
	} {
		if got := renewAllowed(cert(c.lifetime, c.left), now); got != c.want {
			t.Errorf("lifetime %v, %v left: %v, want %v", c.lifetime/day, c.left/day, got, c.want)
		}
	}
}
