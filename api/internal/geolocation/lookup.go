package geolocation

import (
	"fmt"
)

// LookupIP performs a single IP geolocation lookup
func (s *Service) LookupIP(ip string) (*GeoResult, error) {
	s.mu.RLock()
	provider := s.lookupProvider
	s.mu.RUnlock()

	if provider == nil {
		return nil, fmt.Errorf("no lookup provider configured")
	}

	if !provider.IsAvailable() {
		return nil, fmt.Errorf("lookup provider not available")
	}

	res, err := provider.Lookup(ip)
	if err != nil || res == nil {
		return res, err
	}
	s.enrich(ip, res) // add ASN + proxy fields when those DBs are loaded (no-op otherwise)
	return res, nil
}

// LookupBulk performs bulk IP geolocation lookups
func (s *Service) LookupBulk(ips []string) (map[string]*GeoResult, map[string]string) {
	results := make(map[string]*GeoResult)
	errors := make(map[string]string)

	s.mu.RLock()
	provider := s.lookupProvider
	s.mu.RUnlock()

	if provider == nil {
		for _, ip := range ips {
			errors[ip] = "no lookup provider configured"
		}
		return results, errors
	}

	if !provider.IsAvailable() {
		for _, ip := range ips {
			errors[ip] = "lookup provider not available"
		}
		return results, errors
	}

	// Use provider's bulk lookup if available
	providerResults := provider.LookupBulk(ips)
	for _, ip := range ips {
		result, ok := providerResults[ip]
		if !ok {
			// Try individual lookup for missing results
			var err error
			if result, err = provider.Lookup(ip); err != nil {
				errors[ip] = err.Error()
				continue
			}
		}
		if result != nil {
			s.enrich(ip, result) // ASN/proxy/reputation — same enrichment as single lookups
			results[ip] = result
		}
	}

	return results, errors
}

// IsLookupAvailable returns whether IP lookup is available
func (s *Service) IsLookupAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lookupProvider != nil && s.lookupProvider.IsAvailable()
}
