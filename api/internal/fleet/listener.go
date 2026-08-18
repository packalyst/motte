package fleet

import (
	"crypto/tls"
	"net/http"
)

// tlsConfig builds the fleet listener's TLS config. The server cert is signed by
// our CA (so an agent that pinned the CA fingerprint can verify us) and carries
// every non-loopback host IP + the SSL domain as SANs — so it's valid whether the
// agent reaches the panel over WireGuard or the public address. ClientAuth is
// VerifyClientCertIfGiven: /enroll is reachable without a client cert (token-gated),
// but any cert presented must be CA-signed — so the report/command endpoints reject
// certless or foreign-cert connections at the TLS handshake, before any handler.
func (s *Service) tlsConfig() (*tls.Config, error) {
	serverCert, err := s.ca.ServerCertificate(detectHostSANs(s.sslDomain))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.ca.Pool(),
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Handler is the fleet listener's mux. /enroll is token-gated; report/command
// endpoints are mTLS-gated via requireClientCert.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", s.HandleEnroll)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "ca": s.ca.Fingerprint()})
	})
	mux.HandleFunc("POST /report", s.requireClientCert(s.HandleReport))
	mux.HandleFunc("GET /commands", s.requireClientCert(s.HandleCommands))
	mux.HandleFunc("POST /commands/ack", s.requireClientCert(s.HandleCommandAck))
	return mux
}
