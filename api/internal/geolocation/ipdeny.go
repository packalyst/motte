package geolocation

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// IPDenyProvider provides country CIDR ranges from ipdeny.com
type IPDenyProvider struct {
	db *sql.DB
}

// NewIPDenyProvider creates a new ipdeny provider
func NewIPDenyProvider(db *sql.DB) *IPDenyProvider {
	return &IPDenyProvider{db: db}
}

// Name returns the provider name
func (p *IPDenyProvider) Name() string {
	return "ipdeny"
}

// Close closes the provider (no-op for ipdeny)
func (p *IPDenyProvider) Close() error {
	return nil
}

// NeedsUpdate checks if any cached zones are older than 7 days
func (p *IPDenyProvider) NeedsUpdate() bool {
	if p.db == nil {
		return false
	}

	var count int
	err := p.db.QueryRow(`
		SELECT COUNT(*) FROM country_zones_cache c
		INNER JOIN firewall_entries f ON c.country_code = f.value
		WHERE f.entry_type = 'country' AND f.enabled = 1 AND c.updated_at < datetime('now', '-7 days')
	`).Scan(&count)

	if err != nil {
		return false
	}
	return count > 0
}

// Update refreshes all blocked country zones
func (p *IPDenyProvider) Update() error {
	updated, errors := p.RefreshAllZones()
	if errors > 0 && updated == 0 {
		return fmt.Errorf("failed to update any zones, %d errors", errors)
	}
	return nil
}

// LastUpdated returns the most recent zone update time
func (p *IPDenyProvider) LastUpdated() time.Time {
	if p.db == nil {
		return time.Time{}
	}

	var updatedAt string
	err := p.db.QueryRow("SELECT MAX(updated_at) FROM country_zones_cache").Scan(&updatedAt)
	if err != nil {
		return time.Time{}
	}

	t, _ := time.Parse("2006-01-02 15:04:05", updatedAt)
	return t
}

// FetchCountryZones fetches IP zones for a country from ipdeny.com
func (p *IPDenyProvider) FetchCountryZones(countryCode string) (string, error) {
	countryCode = strings.ToLower(countryCode)
	url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", countryCode)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Clean up the zones - remove comments and empty lines
	var cleanZones []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			cleanZones = append(cleanZones, line)
		}
	}

	return strings.Join(cleanZones, "\n"), nil
}

// RefreshAllZones refreshes zones for all blocked countries
func (p *IPDenyProvider) RefreshAllZones() (int, int) {
	if p.db == nil {
		return 0, 1
	}

	rows, err := p.db.Query("SELECT value FROM firewall_entries WHERE entry_type = 'country' AND enabled = 1")
	if err != nil {
		return 0, 1
	}
	defer rows.Close()

	var countryCodes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			continue
		}
		countryCodes = append(countryCodes, code)
	}

	updated := 0
	errors := 0
	for _, code := range countryCodes {
		zones, err := p.FetchCountryZones(code)
		if err != nil {
			log.Printf("Error fetching zones for %s: %v", code, err)
			errors++
			continue
		}

		_, err = p.db.Exec(`
			INSERT INTO country_zones_cache (country_code, zones, updated_at)
			VALUES (?, ?, datetime('now'))
			ON CONFLICT(country_code) DO UPDATE SET zones = ?, updated_at = datetime('now')
		`, code, zones, zones)
		if err != nil {
			log.Printf("Error caching zones for %s: %v", code, err)
			errors++
			continue
		}

		updated++
		log.Printf("Refreshed zones for %s: %d ranges", code, strings.Count(zones, "\n")+1)
	}

	return updated, errors
}

// parseZonesToCIDRs parses a zones string into a slice of CIDRs
func parseZonesToCIDRs(zones string) []string {
	var cidrs []string
	for _, line := range strings.Split(zones, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			cidrs = append(cidrs, line)
		}
	}
	return cidrs
}

// GetCountryCIDRs returns CIDR ranges for a specific country
func (p *IPDenyProvider) GetCountryCIDRs(countryCode string) ([]string, error) {
	if p.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	var zones string
	err := p.db.QueryRow("SELECT zones FROM country_zones_cache WHERE country_code = ?", countryCode).Scan(&zones)
	if err != nil {
		return nil, err
	}

	return parseZonesToCIDRs(zones), nil
}

// GetAllBlockedCIDRs returns all CIDRs for enabled blocked countries
func (p *IPDenyProvider) GetAllBlockedCIDRs(outboundOnly bool) ([]string, error) {
	if p.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	// Query firewall_entries for blocked countries and join with country_zones_cache
	var query string
	if outboundOnly {
		query = `SELECT c.zones FROM country_zones_cache c
			INNER JOIN firewall_entries f ON c.country_code = f.value
			WHERE f.entry_type = 'country' AND f.enabled = 1 AND f.direction = 'both'`
	} else {
		query = `SELECT c.zones FROM country_zones_cache c
			INNER JOIN firewall_entries f ON c.country_code = f.value
			WHERE f.entry_type = 'country' AND f.enabled = 1`
	}

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var allCIDRs []string
	for rows.Next() {
		var zones string
		if err := rows.Scan(&zones); err != nil {
			continue
		}
		allCIDRs = append(allCIDRs, parseZonesToCIDRs(zones)...)
	}

	return allCIDRs, nil
}

// GetCachedZones returns cached zones for a country
func (p *IPDenyProvider) GetCachedZones(countryCode string) (string, error) {
	if p.db == nil {
		return "", fmt.Errorf("database not available")
	}

	var zones string
	err := p.db.QueryRow("SELECT zones FROM country_zones_cache WHERE country_code = ?", countryCode).Scan(&zones)
	return zones, err
}

// CacheZones stores zones for a country in the cache
func (p *IPDenyProvider) CacheZones(countryCode, zones string) error {
	if p.db == nil {
		return fmt.Errorf("database not available")
	}

	_, err := p.db.Exec(`
		INSERT INTO country_zones_cache (country_code, zones, updated_at)
		VALUES (?, ?, datetime('now'))
		ON CONFLICT(country_code) DO UPDATE SET zones = ?, updated_at = datetime('now')
	`, countryCode, zones, zones)
	return err
}

// DeleteCachedZones removes cached zones for a country
func (p *IPDenyProvider) DeleteCachedZones(countryCode string) error {
	if p.db == nil {
		return fmt.Errorf("database not available")
	}

	_, err := p.db.Exec("DELETE FROM country_zones_cache WHERE country_code = ?", countryCode)
	return err
}
