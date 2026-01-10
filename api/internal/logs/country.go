package logs

import (
	"log"
	"time"

	"api/internal/geolocation"
)

// runCountryUpdater periodically updates NULL country fields
func (s *Service) runCountryUpdater() {
	ticker := time.NewTicker(time.Duration(s.config.CountryInterval) * time.Minute)
	defer ticker.Stop()

	// Run once at startup after a short delay
	time.Sleep(30 * time.Second)
	s.updateCountries()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Country updater stopping")
			return
		case <-ticker.C:
			s.updateCountries()
		}
	}
}

// updateCountries bulk updates NULL country fields
func (s *Service) updateCountries() {
	geoSvc := geolocation.GetService()
	if geoSvc == nil || !geoSvc.IsLookupAvailable() {
		return
	}

	// Update source countries (for inbound/dns where we care about requester location)
	s.updateSourceCountries(geoSvc)

	// Update destination countries (for outbound where we care about where traffic goes)
	s.updateDestCountries(geoSvc)
}

// updateSourceCountries updates logs_src_country for entries with NULL
func (s *Service) updateSourceCountries(geoSvc *geolocation.Service) {
	s.updateCountryColumn(geoSvc,
		`SELECT logs_id, logs_src_ip FROM logs WHERE logs_src_country IS NULL OR logs_src_country = '' LIMIT ?`,
		"logs_src_country",
		"source",
	)
}

// updateDestCountries updates logs_dest_country for outbound entries with NULL
func (s *Service) updateDestCountries(geoSvc *geolocation.Service) {
	s.updateCountryColumn(geoSvc,
		`SELECT logs_id, logs_dest_ip FROM logs WHERE logs_type = 'outbound' AND logs_dest_ip IS NOT NULL AND (logs_dest_country IS NULL OR logs_dest_country = '') LIMIT ?`,
		"logs_dest_country",
		"destination",
	)
}

// updateCountryColumn is the shared implementation for country updates
func (s *Service) updateCountryColumn(geoSvc *geolocation.Service, selectQuery, column, label string) {
	rows, err := s.db.Query(selectQuery, s.config.CountryBatchSize)
	if err != nil {
		return
	}
	defer rows.Close()

	updates := make(map[int64]string)
	for rows.Next() {
		var id int64
		var ip string
		if err := rows.Scan(&id, &ip); err != nil {
			continue
		}
		if result, err := geoSvc.LookupIP(ip); err == nil && result != nil && result.CountryCode != "" {
			updates[id] = result.CountryCode
		}
	}

	if len(updates) == 0 {
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		return
	}

	stmt, err := tx.Prepare("UPDATE logs SET " + column + " = ? WHERE logs_id = ?")
	if err != nil {
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for id, country := range updates {
		stmt.Exec(country, id)
	}

	if err := tx.Commit(); err == nil {
		log.Printf("Updated %d %s countries", len(updates), label)
	}
}
