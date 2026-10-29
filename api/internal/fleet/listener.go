package fleet

import (
	"crypto/tls"
	"net/http"
)

// tlsConfig builds the fleet listener's TLS config. The server cert is signed by
// our CA (so an agent that pinned the CA fingerprint can verify us) and carries
// every non-loopback host IP + the SSL domain as SANs — so it's valid whether the
// agent reaches the panel over WireGuard or the public address; serverCertificate
// keeps it current. ClientAuth is VerifyClientCertIfGiven: /enroll is reachable
// without a client cert (token-gated), but any cert presented must be CA-signed —
// so the report/command endpoints reject certless or foreign-cert connections at
// the TLS handshake, before any handler.
func (s *Service) tlsConfig() (*tls.Config, error) {
	if _, err := s.serverCertificate(nil); err != nil { // fail at start, not at the first agent
		return nil, err
	}
	return &tls.Config{
		// Per handshake, so a CA rotation changes the accepted client CAs without a restart.
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return s.handshakeConfig(), nil },
		MinVersion:         tls.VersionTLS12,
	}, nil
}

// handshakeConfig is one handshake's TLS config: the current listener certificate, and client
// certificates accepted from every current CA. No session resumption: a resumed session skips the
// client-certificate check, so a machine cut off by a CA change could carry on in an old session.
func (s *Service) handshakeConfig() *tls.Config {
	return &tls.Config{
		GetCertificate:         s.serverCertificate,
		ClientAuth:             tls.VerifyClientCertIfGiven,
		ClientCAs:              s.cas.Load().pool(),
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}
}

// Handler is the fleet listener's mux. /enroll is token-gated; report/command
// endpoints are mTLS-gated via requireClientCert.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", s.HandleEnroll)
	// NOTE: the /agent install script is NOT served here. It's published on the main api
	// router via Traefik/443 (see HandleInstallScript + fleetroute.go) so the download
	// has the panel's real cert and rides Traefik's rate-limit/blocklist middleware —
	// one guarded door. This listener is only the mTLS channel (enroll/report/commands).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "ca": s.CA().Fingerprint()})
	})
	mux.HandleFunc("POST /report", s.requireClientCert(s.HandleReport))
	mux.HandleFunc("POST /cve-report", s.requireClientCert(s.HandleCVEReport))
	mux.HandleFunc("POST /scan-failure", s.requireClientCert(s.HandleScanFailure))
	mux.HandleFunc("POST /fim-report", s.requireClientCert(s.HandleFIMReport))
	mux.HandleFunc("GET /commands", s.requireClientCert(s.HandleCommands))
	mux.HandleFunc("POST /commands/ack", s.requireClientCert(s.HandleCommandAck))
	mux.HandleFunc("POST /deregister", s.requireClientCert(s.HandleDeregister))
	mux.HandleFunc("GET /console", s.requireClientCert(s.HandleConsoleChannel)) // persistent console channel (point 7)
	mux.HandleFunc("GET /link", s.requireClientCert(s.HandleLink))              // doorbell + presence (link.go)
	mux.HandleFunc("POST /renew", s.requireClientCert(s.HandleRenew))           // client-cert renewal (renew.go)
	mux.HandleFunc("GET /trust", s.requireClientCert(s.HandleTrust))            // the CAs the agent should trust (trust.go)
	// Agent self-update: enrolled agents pull their own binary from the panel over this
	// mTLS channel (verifying the release signature themselves), instead of the forge.
	mux.HandleFunc("GET /update", s.requireClientCert(s.HandleAgentUpdateInfo))
	mux.HandleFunc("GET /update/binary", s.requireClientCert(s.HandleAgentUpdateBinary))
	return mux
}
