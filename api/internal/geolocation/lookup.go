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

	return provider.Lookup(ip)
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
		if result, ok := providerResults[ip]; ok {
			results[ip] = result
		} else {
			// Try individual lookup for missing results
			if result, err := provider.Lookup(ip); err == nil {
				results[ip] = result
			} else {
				errors[ip] = err.Error()
			}
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

