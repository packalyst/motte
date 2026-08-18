package fleet

import (
	"context"
	"net/http"
)

type ctxKey int

const machineCtxKey ctxKey = 0

// requireClientCert gates the report/command endpoints. The TLS layer has already
// verified any presented client cert against our CA (VerifyClientCertIfGiven), so
// here we (a) require a cert was presented and (b) confirm its fingerprint maps to
// an enrolled, non-revoked machine. Both must hold — a valid-but-unregistered cert,
// or a revoked one, is rejected.
func (s *Service) requireClientCert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeErr(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		fp := fingerprintFromCert(r.TLS.PeerCertificates[0])
		m, err := s.machineByCertFP(fp)
		if err != nil || m == nil {
			writeErr(w, http.StatusUnauthorized, "unknown or revoked client certificate")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), machineCtxKey, m)))
	}
}

// machineFrom returns the authenticated machine attached by requireClientCert.
func machineFrom(r *http.Request) *Machine {
	m, _ := r.Context().Value(machineCtxKey).(*Machine)
	return m
}
