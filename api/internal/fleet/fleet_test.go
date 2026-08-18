package fleet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"api/internal/helper"

	_ "github.com/mattn/go-sqlite3"
)

func init() {
	// deterministic key for tests
	_ = helper.InitEncryption // ensure symbol
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	t.Setenv("ENCRYPTION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	helper.InitEncryption()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	svc, err := New(db, "", "panel.example", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// makeCSR returns a fresh EC key + a CSR PEM, as an agent would.
func makeCSR(t *testing.T, cn string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestCAPersistsAcrossReload(t *testing.T) {
	svc := newTestService(t)
	fp1 := svc.CA().Fingerprint()

	// Re-open a Service against the same DB — must load the SAME CA, not regenerate.
	svc2, err := New(svc.db, svc.installURL, svc.sslDomain, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if svc2.CA().Fingerprint() != fp1 {
		t.Fatal("CA fingerprint changed on reload — key not persisted/loaded")
	}
	if fp1 == "" || len(svc.CA().CertPEM()) == 0 {
		t.Fatal("empty CA")
	}
}

func TestTokenSingleUseAndExpiry(t *testing.T) {
	svc := newTestService(t)

	tok, err := svc.CreateToken("web-01", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.redeemToken(tok.Plaintext); err != nil {
		t.Fatalf("first redeem should succeed: %v", err)
	}
	if _, err := svc.redeemToken(tok.Plaintext); err == nil {
		t.Fatal("second redeem MUST fail (single-use)")
	}
	if _, err := svc.redeemToken("totally-bogus"); err == nil {
		t.Fatal("bogus token must fail")
	}

	// expired token — insert an already-past row directly (CreateToken clamps ttl>0)
	if _, err := svc.db.Exec(
		`INSERT INTO fleet_tokens (token_hash, label, expires_at, created_at) VALUES (?, 'old', ?, ?)`,
		hashToken("expired-tok"),
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.redeemToken("expired-tok"); err == nil {
		t.Fatal("expired token must fail")
	}
}

func TestEnrollEndToEnd(t *testing.T) {
	svc := newTestService(t)
	tok, _ := svc.CreateToken("web-01", time.Hour)
	_, csrPEM := makeCSR(t, "agent")

	body, _ := json.Marshal(enrollRequest{
		Token: tok.Plaintext, CSR: string(csrPEM),
		MachineID: "machineid-abc", Hostname: "web-01", WGPubkey: "WGKEY==",
	})
	rr := httptest.NewRecorder()
	svc.HandleEnroll(rr, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp enrollResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	// the issued client cert must CHAIN TO THE PANEL CA and be a client cert
	leafB, _ := pem.Decode([]byte(resp.ClientCert))
	leaf, err := x509.ParseCertificate(leafB.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     svc.CA().Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued cert does not chain to the panel CA: %v", err)
	}
	if leaf.Subject.CommonName != resp.MachineID {
		t.Fatalf("cert CN %q != assigned machine id %q", leaf.Subject.CommonName, resp.MachineID)
	}

	// the returned CA must match the panel CA
	if resp.CACert != string(svc.CA().CertPEM()) {
		t.Fatal("returned ca_cert != panel CA")
	}

	// machine recorded, fingerprint matches the mTLS lookup path
	machines, _ := svc.ListMachines()
	if len(machines) != 1 || machines[0].ID != resp.MachineID {
		t.Fatalf("machine not recorded: %+v", machines)
	}
	if m, _ := svc.machineByCertFP(fingerprintFromCert(leaf)); m == nil || m.ID != resp.MachineID {
		t.Fatal("machineByCertFP did not find the enrolled machine by its cert fingerprint")
	}

	// token is now spent — a second enroll with it must be rejected
	rr2 := httptest.NewRecorder()
	svc.HandleEnroll(rr2, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body)))
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("reused token should give 401, got %d", rr2.Code)
	}
}

func TestEnrollRejectsBadInputs(t *testing.T) {
	svc := newTestService(t)

	// bad token
	_, csrPEM := makeCSR(t, "agent")
	body, _ := json.Marshal(enrollRequest{Token: "nope", CSR: string(csrPEM)})
	rr := httptest.NewRecorder()
	svc.HandleEnroll(rr, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad token want 401, got %d", rr.Code)
	}

	// valid token but garbage CSR
	tok, _ := svc.CreateToken("x", time.Hour)
	body2, _ := json.Marshal(enrollRequest{Token: tok.Plaintext, CSR: "not a pem"})
	rr2 := httptest.NewRecorder()
	svc.HandleEnroll(rr2, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body2)))
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("garbage CSR want 400, got %d", rr2.Code)
	}
}
