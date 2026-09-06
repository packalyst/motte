package geolocation

import (
	"context"
	"log"
	"time"

	"api/internal/routines"
	"api/internal/settings"
)

// registerUpdateRoutine registers the daily geo-data update with the supervisor.
// The next fire is the configured hour-of-day (read live, so a changed hour is
// picked up on the next reschedule); the run itself no-ops when auto-update is
// off, so toggling it needs no restart.
func (s *Service) registerUpdateRoutine() {
	routines.Register(routines.Spec{
		Name:        "geo-update",
		Description: "Update geolocation databases (lookup / ASN / proxy / blocking)",
		Schedule:    "daily at configured hour",
		NextRun: func(now time.Time) time.Time {
			s.mu.RLock()
			hour := s.config.UpdateHour
			s.mu.RUnlock()
			n := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
			if !n.After(now) {
				n = n.Add(24 * time.Hour)
			}
			return n
		},
		Run: func(context.Context) error {
			s.mu.RLock()
			enabled := s.config.AutoUpdate
			updateServices := s.config.UpdateServices
			s.mu.RUnlock()
			if !enabled {
				return nil // scheduled fire, but auto-update is off
			}
			log.Printf("Running scheduled geolocation update at %s", time.Now().Format(time.RFC3339))
			s.runScheduledUpdate(updateServices)
			return nil
		},
	})
}

// runScheduledUpdate performs the scheduled update based on settings
func (s *Service) runScheduledUpdate(updateServices string) {
	switch updateServices {
	case "all":
		s.updateLookupProvider()
		s.updateEnrichmentDBs()
		s.updateBlockingProvider()
	case "lookup":
		s.updateLookupProvider()
		s.updateEnrichmentDBs()
	case "blocking":
		s.updateBlockingProvider()
	default:
		s.updateLookupProvider()
		s.updateEnrichmentDBs()
		s.updateBlockingProvider()
	}
}

// updateLookupProvider updates the lookup provider (MaxMind or IP2Location)
func (s *Service) updateLookupProvider() {
	s.mu.RLock()
	provider := s.lookupProvider
	s.mu.RUnlock()

	if provider == nil {
		return
	}

	log.Printf("Updating lookup provider: %s", provider.Name())
	if err := provider.Update(); err != nil {
		log.Printf("Error updating lookup provider: %v", err)
		return
	}

	// Update last update timestamp
	settings.SetSetting("geo_last_update_lookup", time.Now().Format(time.RFC3339))
	log.Printf("Lookup provider %s updated successfully", provider.Name())
}

// updateBlockingProvider updates the blocking provider (ipdeny zones)
func (s *Service) updateBlockingProvider() {
	if !s.IsBlockingEnabled() {
		return
	}

	s.mu.RLock()
	provider := s.blockingProvider
	s.mu.RUnlock()

	if provider == nil {
		return
	}

	log.Printf("Updating blocking provider: %s", provider.Name())
	updated, errors := provider.RefreshAllZones()

	if updated > 0 {
		// Trigger nftables apply after zone update
		if s.nft != nil {
			s.nft.RequestApply()
		}
	}

	// Update last update timestamp
	settings.SetSetting("geo_last_update_blocking", time.Now().Format(time.RFC3339))
	log.Printf("Blocking provider update complete: %d updated, %d errors", updated, errors)
}

// updateEnrichmentDBs downloads the enabled ASN/proxy add-on DBs and reloads them.
// Called by both the manual "Update Now" and the auto-update scheduler, alongside the
// lookup provider — so one action refreshes everything that's turned on.
func (s *Service) updateEnrichmentDBs() {
	s.mu.RLock()
	asnOn, proxyOn := s.config.ASNEnabled, s.config.ProxyEnabled
	s.mu.RUnlock()

	if asnOn {
		if err := s.downloadEnrichmentCSV(s.enrichmentFileCode("asn"), s.asnDBPath()); err != nil {
			log.Printf("geolocation: ASN DB update failed: %v", err)
		}
	}
	if proxyOn {
		if err := s.downloadEnrichmentCSV(s.enrichmentFileCode("proxy"), s.proxyDBPath()); err != nil {
			log.Printf("geolocation: proxy DB update failed: %v", err)
		}
	}
	if asnOn || proxyOn {
		s.loadEnrichmentDBs()
	}
}

// TriggerUpdate manually triggers an update
func (s *Service) TriggerUpdate(updateServices string) (map[string]string, error) {
	results := make(map[string]string)

	switch updateServices {
	case "lookup":
		s.updateLookupProvider()
		s.updateEnrichmentDBs()
		results["lookup"] = "update triggered"
	case "blocking":
		s.updateBlockingProvider()
		results["blocking"] = "update triggered"
	default:
		s.updateLookupProvider()
		s.updateEnrichmentDBs()
		s.updateBlockingProvider()
		results["lookup"] = "update triggered"
		results["blocking"] = "update triggered"
	}

	return results, nil
}
