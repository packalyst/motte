package geolocation

import (
	"log"
	"time"

	"api/internal/settings"
)

// runUpdateScheduler runs the unified geo data update scheduler
func (s *Service) runUpdateScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	lastRunDate := ""

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Geolocation update scheduler stopping")
			return
		case <-ticker.C:
			s.mu.RLock()
			enabled := s.config.AutoUpdate
			targetHour := s.config.UpdateHour
			updateServices := s.config.UpdateServices
			s.mu.RUnlock()

			if !enabled {
				continue
			}

			now := time.Now()
			currentDate := now.Format("2006-01-02")
			currentHour := now.Hour()

			// Only run once per day at the target hour
			if currentHour == targetHour && currentDate != lastRunDate {
				log.Printf("Running scheduled geolocation update at %s", now.Format(time.RFC3339))
				s.runScheduledUpdate(updateServices)
				lastRunDate = currentDate
			}
		}
	}
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
