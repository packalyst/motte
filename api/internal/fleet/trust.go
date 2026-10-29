package fleet

import (
	"encoding/pem"
	"net/http"
)

// The CAs an agent should trust. An agent pinned the panel CA at enrollment; it asks this
// periodically (over mTLS, so only from the panel it already trusts) and keeps exactly these CAs,
// adding a new one only when a CA it already trusts vouches for it (a cross-signed copy in
// "cross"), and never dropping its last.

type trustResponse struct {
	CAs    []string `json:"cas"`    // PEM, every CA the agent should trust
	Cross  []string `json:"cross"`  // PEM, each new CA signed by an older one, proving it
	Issuer string   `json:"issuer"` // fingerprint of the CA renewals come from: a cert from another renews now
}

// HandleTrust (GET /trust, mTLS).
func (s *Service) HandleTrust(w http.ResponseWriter, r *http.Request) {
	set := s.cas.Load()
	resp := trustResponse{CAs: []string{string(set.serving().CertPEM())}, Cross: []string{}, Issuer: set.active.Fingerprint()}
	if set.rotating() {
		resp.CAs = append(resp.CAs, string(set.active.CertPEM()))
		resp.Cross = append(resp.Cross, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: set.cross.Raw})))
	}
	writeJSON(w, http.StatusOK, resp)
}
