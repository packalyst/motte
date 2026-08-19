package fleet

import (
	"api/internal/helper"
	"api/internal/traefik"
)

// ApplyInstallRoute reconciles the Traefik /agent route (traefik/dynamic/fleet.yml) to
// the current state: it exists only when the fleet listener is ON and a panel domain is
// configured, and carries sentinel_fw_block only when the "Enforce Firewall on Proxied
// Traffic" setting is on. Called from ReloadFromSettings (fleet toggle) and, via the
// traefik.RegenerateFleetRoute hook, when that firewall setting flips — the same pattern
// domain routes use. Safe to call repeatedly (write/remove are idempotent).
func (s *Service) ApplyInstallRoute() error {
	s.mu.Lock()
	enabled := s.srv != nil
	domain := s.sslDomain
	s.mu.Unlock()

	dir := helper.GetEnvOptional("TRAEFIK_CONFIG", "/traefik/dynamic")
	// No domain (bare IP) or listener off ⇒ no public 443 install route. On a bare IP
	// there is no trusted cert for a clean download, so the route simply doesn't exist.
	if !enabled || domain == "" {
		return traefik.RemoveFleetRoute(dir)
	}
	fwOn := s.fwBlockEnabled != nil && s.fwBlockEnabled()
	return traefik.GenerateFleetRoute(dir, domain, helper.GetEnv("API_PORT"), fwOn)
}
