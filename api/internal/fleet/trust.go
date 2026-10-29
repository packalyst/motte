package fleet

import "net/http"

// The CAs an agent should trust. An agent pinned the panel CA at enrollment; it asks this
// periodically (over mTLS, so only from the panel it already trusts) and keeps exactly these CAs,
// adding a new one only when a CA it already trusts vouches for it (a cross-signed copy in
// "cross"), and never dropping its last.

type trustResponse struct {
	CAs   []string `json:"cas"`   // PEM, every CA the agent should trust
	Cross []string `json:"cross"` // PEM, each new CA signed by an older one, proving it
}

// HandleTrust (GET /trust, mTLS).
func (s *Service) HandleTrust(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, trustResponse{CAs: []string{string(s.ca.CertPEM())}, Cross: []string{}})
}
