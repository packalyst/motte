// Package fleet implements the panel side of the "panel tie" (Phase 2): it is a
// private certificate authority + enrollment service that lets per-machine agents
// (motte-agent) register once with a one-time token, obtain a client certificate, and
// then talk to the panel over mutual TLS. The panel only ever obeys agents whose
// certificate its own CA signed and that map to an enrolled, non-revoked machine.
//
// Security posture (no shortcuts):
//   - The CA private key is generated on the panel and stored ENCRYPTED at rest
//     (AES-256-GCM via ENCRYPTION_SECRET). It never leaves the panel.
//   - Agents generate their own keypair locally; the panel only ever sees a CSR
//     (public half) and signs it. Private keys never transit.
//   - Enrollment tokens are single-use, short-lived, and stored only as a hash.
//   - Client certs are short-lived and bound to a machine identity.
package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"api/internal/helper"
)

// CA is one of the panel's certificate authorities.
type CA struct {
	id      int64 // its fleet_ca row
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

// newCA makes a CA key and self-signed certificate (10 years) named name, and returns it with
// the key encrypted under ENCRYPTION_SECRET, ready to store.
func newCA(name string) (*CA, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0), // 10y
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // leaf-only issuance
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	keyEnc, err := helper.Encrypt(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	if err != nil {
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", err
	}
	return &CA{cert: cert, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key}, keyEnc, nil
}

// insertCA stores a CA in state ("active" | "previous") with an optional cross-signed copy.
func insertCA(db interface {
	Exec(string, ...any) (sql.Result, error)
}, ca *CA, keyEnc, state, crossPEM string) error {
	res, err := db.Exec(`INSERT INTO fleet_ca (cert_pem, key_enc, created_at, state, cross_pem) VALUES (?, ?, ?, ?, ?)`,
		string(ca.certPEM), keyEnc, time.Now().UTC().Format(time.RFC3339), state, sql.NullString{String: crossPEM, Valid: crossPEM != ""})
	if err != nil {
		return err
	}
	ca.id, err = res.LastInsertId()
	return err
}

func parseCA(certPEM, keyEnc string) (*CA, error) {
	keyPEM, err := helper.Decrypt(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt CA key: %w", err)
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return nil, fmt.Errorf("CA key PEM invalid")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode([]byte(certPEM))
	if cb == nil {
		return nil, fmt.Errorf("CA cert PEM invalid")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, certPEM: []byte(certPEM), key: key}, nil
}

// CertPEM returns the CA certificate (the trust anchor agents pin).
func (c *CA) CertPEM() []byte { return c.certPEM }

// Fingerprint returns the SHA-256 fingerprint of the CA cert, as "sha256:<hex>".
// This is what the install command pins out-of-band.
func (c *CA) Fingerprint() string { return fingerprintFromCert(c.cert) }

// SignClientCSR verifies a CSR and issues a short-lived CLIENT certificate bound
// to commonName. The CSR's own signature is checked; only its public key is used.
func (c *CA) SignClientCSR(csrDER []byte, commonName string, validity time.Duration) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature invalid: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// ServerCertificate mints an ephemeral SERVER certificate (signed by the CA) for
// the fleet mTLS listener, valid for the given hostnames/IPs for ttl. It's held in
// memory (see serverCertificate); the served chain includes the CA so an agent that
// pinned the CA can verify it.
func (c *CA) ServerCertificate(hosts []string, ttl time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "motte-panel"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw}, // leaf + CA chain
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func randomSerial() (*big.Int, error) {
	// 128-bit random serial.
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
