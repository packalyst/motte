package fleet

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	certPEM, err := svc.ca.SignClientCSR(b.Bytes, id, ttl)
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
	old, oldPEM := issueCert(t, svc, "m1", 10*24*time.Hour) // inside the renewal window
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
	if _, err := renewed.Verify(x509.VerifyOptions{Roots: svc.CA().Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil || renewed.Subject.CommonName != "m1" {
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

	// A cert with plenty of life left can't be renewed.
	fresh, freshPEM := issueCert(t, svc, "m2", 90*24*time.Hour)
	_ = svc.registerMachine(Machine{ID: "m2", Name: "m2", CertFP: certFingerprintPEM(freshPEM), EnrolledAt: time.Now()})
	if rr := callAs(svc, svc.HandleRenew, fresh, body); rr.Code != http.StatusConflict {
		t.Fatalf("early renewal: %d, want 409", rr.Code)
	}

	// A revoked machine can't renew.
	_, _ = svc.db.Exec(`UPDATE fleet_machines SET revoked = 1 WHERE id = 'm1'`)
	if rr := callAs(svc, svc.HandleRenew, renewed, body); rr.Code != http.StatusUnauthorized {
		t.Fatalf("revoked renewal: %d, want 401", rr.Code)
	}
}
