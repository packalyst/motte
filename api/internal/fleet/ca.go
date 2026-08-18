// Package fleet implements the panel side of the "panel tie" (Phase 2): it is a
// private certificate authority + enrollment service that lets per-machine agents
// (wgscout) register once with a one-time token, obtain a client certificate, and
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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"api/internal/helper"
)

// CA is the panel's internal certificate authority.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

// loadOrCreateCA returns the panel CA, generating + persisting it on first use.
// The CA cert is stored in the clear (it's public); the private key is stored
// encrypted with the panel's ENCRYPTION_SECRET.
func loadOrCreateCA(db *sql.DB) (*CA, error) {
	var certPEM, keyEnc string
	err := db.QueryRow(`SELECT cert_pem, key_enc FROM fleet_ca WHERE id = 1`).Scan(&certPEM, &keyEnc)
	switch err {
	case nil:
		return parseCA(certPEM, keyEnc)
	case sql.ErrNoRows:
		return generateCA(db)
	default:
		return nil, err
	}
}

func generateCA(db *sql.DB) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wgscout-panel-ca"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0), // 10y
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // leaf-only issuance
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyEnc, err := helper.Encrypt(string(keyPEM))
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`INSERT INTO fleet_ca (id, cert_pem, key_enc, created_at) VALUES (1, ?, ?, ?)`,
		string(certPEM), keyEnc, now.UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, certPEM: certPEM, key: key}, nil
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
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Pool returns a CertPool containing just this CA (for verifying agent client certs).
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

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
// the fleet mTLS listener, valid for the given hostnames/IPs. It's regenerated at
// startup and held in memory; the served chain includes the CA so an agent that
// pinned the CA can verify it.
func (c *CA) ServerCertificate(hosts []string) (tls.Certificate, error) {
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
		Subject:      pkix.Name{CommonName: "wgscout-panel"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
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
