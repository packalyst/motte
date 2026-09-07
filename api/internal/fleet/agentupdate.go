package fleet

import (
	"net/http"
	"strings"
)

// Agent self-update endpoints, served on the mTLS listener (enrolled machines only). The
// agent pulls its own updates from its panel over the already-trusted CA-pinned channel,
// so it needs no forge access or configuration; only the panel talks to the forge. The
// agent still verifies the ed25519 signature itself (with its own baked-in public key), so
// even a compromised panel cannot feed it a tampered binary.

// HandleAgentUpdateInfo (GET /update) returns the latest release's version plus the signed
// checksums, so the agent can decide whether to update and verify the download.
func (s *Service) HandleAgentUpdateInfo(w http.ResponseWriter, r *http.Request) {
	version, checksums, sig, err := s.agentCache.LatestSigned(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, "panel could not read the latest release")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"version":   version,
		"checksums": checksums,
		"sig":       sig,
	})
}

// HandleAgentUpdateBinary (GET /update/binary?arch=) streams the checksum-verified agent
// binary for the requested architecture.
func (s *Service) HandleAgentUpdateBinary(w http.ResponseWriter, r *http.Request) {
	arch, ok := archAlias[strings.ToLower(strings.TrimSpace(r.URL.Query().Get("arch")))]
	if !ok {
		writeErr(w, http.StatusBadRequest, "unsupported architecture")
		return
	}
	bin, err := s.agentCache.Binary(r.Context(), arch)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "panel could not fetch the agent binary")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(bin)
}
