package fleet

import (
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"strings"
	"time"
)

const maxEnrollBody = 1 << 16

// enrollRequest is what the agent POSTs to /enroll (over TLS, server verified
// against the pinned CA fingerprint). The agent has no client cert yet — the
// one-time token is the credential.
type enrollRequest struct {
	Token     string `json:"token"`
	CSR       string `json:"csr"`        // PEM CERTIFICATE REQUEST (agent's public half)
	MachineID string `json:"machine_id"` // /etc/machine-id
	Hostname  string `json:"hostname"`
	WGPubkey  string `json:"wg_pubkey,omitempty"`
}

type enrollResponse struct {
	MachineID  string `json:"machine_id"`  // panel-assigned id (= the cert CN)
	ClientCert string `json:"client_cert"` // PEM, signed by the panel CA
	CACert     string `json:"ca_cert"`     // PEM, the trust anchor the agent stores
}

// HandleEnroll is the join door. It runs on the fleet TLS listener and is gated by
// the one-time token (no client cert required here). Steps: redeem token (atomic,
// single-use) -> verify CSR -> sign a short-lived client cert -> record the
// machine -> return the cert + CA.
func (s *Service) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrollBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}

	// Validate the CSR shape BEFORE redeeming the token. redeemToken is a one-shot
	// consume; if we spent it first and the CSR were malformed, the operator would
	// have to mint a fresh token for a retry. Cheap syntactic checks come first.
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		writeErr(w, http.StatusBadRequest, "invalid CSR")
		return
	}

	label, err := s.redeemToken(req.Token)
	if err != nil {
		// Deliberately vague: don't distinguish invalid vs used vs expired.
		writeErr(w, http.StatusUnauthorized, "invalid or used enrollment token")
		return
	}

	id, err := newMachineID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	certPEM, err := s.ca.SignClientCSR(block.Bytes, id, s.clientCertTTL)
	if err != nil {
		log.Printf("fleet: sign csr rejected: %v", err)
		writeErr(w, http.StatusBadRequest, "csr rejected")
		return
	}

	// Sanitize the self-reported hostname before it's stored as the display name: it's
	// fully attacker-controlled at enroll and is later rendered in the UI. Defence in depth
	// alongside output-escaping — a hostile name (e.g. an <img onerror=...> XSS payload)
	// never even lands in the DB.
	name := sanitizeMachineName(req.Hostname)
	if name == "" {
		name = sanitizeMachineName(label)
	}
	if name == "" {
		name = "machine-" + id
	}
	m := Machine{
		ID:          id,
		Name:        name,
		MachineHash: machineIdentityHash(req.MachineID, req.WGPubkey),
		CertFP:      certFingerprintPEM(certPEM),
		WGPubkey:    req.WGPubkey,
		EnrolledAt:  time.Now(),
	}
	if err := s.registerMachine(m); err != nil {
		log.Printf("fleet: register machine: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	log.Printf("fleet: enrolled machine id=%s name=%q (token label=%q)", id, name, label)
	writeJSON(w, http.StatusOK, enrollResponse{
		MachineID:  id,
		ClientCert: string(certPEM),
		CACert:     string(s.ca.CertPEM()),
	})
}

// sanitizeMachineName reduces an untrusted hostname/label to a safe, bounded display
// name: ASCII letters/digits and a few separators (. _ - space) only, capped at 64
// characters. Every other byte — including the < > " ' and control characters an XSS
// payload needs — is dropped, so a hostile value can never reach the DB or the UI.
func sanitizeMachineName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-', r == ' ':
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
