package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAgentAllowed: a certificate gets agentBurst requests at once, then one per agentRefill;
// another certificate has its own bucket.
func TestAgentAllowed(t *testing.T) {
	now := time.Now()
	for i := 0; i < agentBurst; i++ {
		if !agentAllowed("fp-burst", now) {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	if agentAllowed("fp-burst", now) {
		t.Fatal("request past the burst allowed")
	}
	if !agentAllowed("fp-other", now) {
		t.Fatal("another certificate was limited")
	}
	if !agentAllowed("fp-burst", now.Add(agentRefill)) {
		t.Fatal("no request allowed after a refill")
	}
	if agentAllowed("fp-burst", now.Add(agentRefill)) {
		t.Fatal("more than one request allowed per refill")
	}
}

// TestRequireClientCertRateLimited: the real agent entry point answers 429 once a certificate is
// past its burst, before looking the machine up.
func TestRequireClientCertRateLimited(t *testing.T) {
	svc := newTestService(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "synthetic-agent"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	h := svc.requireClientCert(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	call := func() int {
		r := httptest.NewRequest(http.MethodPost, "/report", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		rr := httptest.NewRecorder()
		h(rr, r)
		return rr.Code
	}
	for i := 0; i < agentBurst; i++ {
		if code := call(); code != http.StatusUnauthorized { // not enrolled: refused after the lookup
			t.Fatalf("request %d: %d, want 401 (unknown cert)", i+1, code)
		}
	}
	if code := call(); code != http.StatusTooManyRequests {
		t.Fatalf("past the burst: %d, want 429", code)
	}
}
