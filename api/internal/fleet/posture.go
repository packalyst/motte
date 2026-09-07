package fleet

// Exported accessors for the panel's supply-chain posture (surfaced read-only on the Host
// page). These read already-resolved state — no network, no blocking — so a status endpoint
// can include them cheaply.

// SigningEnabled reports whether release-signature enforcement is compiled into this build
// (a public key was baked in). When false, agent binaries are trusted by sha256 over
// TLS/mTLS only.
func SigningEnabled() bool { return signingEnabled() }

// Port returns the fleet mTLS listener port currently in effect.
func (s *Service) Port() int { return s.effectivePort() }

// AgentVersionCached returns the last-resolved latest agent version (e.g. "0.1.26"), or ""
// if it hasn't been resolved yet. It never triggers a network fetch — callers that want a
// fresh value use the (blocking, cached) LatestVersion path elsewhere.
func (s *Service) AgentVersionCached() string {
	c := s.agentCache
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}
