package geolocation

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/nftables"
	"api/internal/router"
	"api/internal/settings"
)

// Service is the main geolocation service
type Service struct {
	db      *database.DB
	dataDir string
	config  Config

	// Providers
	lookupProvider   Provider     // MaxMind or IP2Location
	blockingProvider CIDRProvider // ipdeny

	// Country configs loaded from file
	countryConfigs map[string]CountryConfig

	// Provider configs loaded from file
	providersConfig ProvidersConfig

	// nftables service for triggering applies after zone refresh
	nft *nftables.Service

	// Thread safety
	mu sync.RWMutex

	// Background tasks
	ctx    context.Context
	cancel context.CancelFunc
}

var serviceInstance *Service

// SetService sets the global service instance
func SetService(s *Service) {
	serviceInstance = s
}

// GetService returns the global service instance
func GetService() *Service {
	return serviceInstance
}

// SetNftService sets the nftables service reference for triggering applies
func (s *Service) SetNftService(nft *nftables.Service) {
	s.nft = nft
}

// New creates a new geolocation service
func New(dataDir string) (*Service, error) {
	db, err := database.GetDB()
	if err != nil {
		log.Printf("Warning: database not initialized for geolocation service: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Service{
		db:             db,
		dataDir:        dataDir,
		countryConfigs: make(map[string]CountryConfig),
		ctx:            ctx,
		cancel:         cancel,
	}

	// Create data directories
	if err := s.ensureDirectories(); err != nil {
		cancel()
		return nil, err
	}

	// Load country configs from file
	s.loadCountryConfigs()

	// Load provider configs from file
	s.loadProvidersConfig()

	// Load configuration from settings
	s.loadConfig()

	// Initialize providers based on config
	if err := s.initProviders(); err != nil {
		log.Printf("Warning: failed to initialize some providers: %v", err)
	}

	// Migrate old firewall settings if they exist
	s.migrateOldSettings()

	// Start background update scheduler
	go s.runUpdateScheduler()

	log.Printf("Geolocation service initialized (lookup: %s, blocking: %v)",
		s.config.LookupProvider, s.config.BlockingEnabled)

	return s, nil
}

// ensureDirectories creates necessary data directories
func (s *Service) ensureDirectories() error {
	dirs := []string{
		s.dataDir,
		filepath.Join(s.dataDir, "maxmind"),
		filepath.Join(s.dataDir, "ip2location"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}

// loadCountryConfigs loads country metadata from JSON file
func (s *Service) loadCountryConfigs() {
	configPath := helper.CountriesConfigPath
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Warning: failed to load country configs from %s: %v", configPath, err)
		return
	}

	if err := json.Unmarshal(data, &s.countryConfigs); err != nil {
		log.Printf("Warning: failed to parse country configs: %v", err)
		return
	}

	log.Printf("Loaded %d country configs", len(s.countryConfigs))
}

// loadProvidersConfig loads provider configurations from JSON file
func (s *Service) loadProvidersConfig() {
	configPath := helper.GeolocationConfigPath
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Warning: failed to load providers config from %s: %v", configPath, err)
		return
	}

	if err := json.Unmarshal(data, &s.providersConfig); err != nil {
		log.Printf("Warning: failed to parse providers config: %v", err)
		return
	}

	log.Printf("Loaded %d provider configs", len(s.providersConfig.Providers))
}

// loadConfig loads configuration from settings
func (s *Service) loadConfig() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Lookup provider
	if val, err := settings.GetSetting("geo_lookup_provider"); err == nil && val != "" {
		s.config.LookupProvider = val
	} else {
		s.config.LookupProvider = "none"
	}

	// Blocking enabled
	if val, err := settings.GetSetting("geo_blocking_enabled"); err == nil {
		s.config.BlockingEnabled, _ = strconv.ParseBool(val)
	}

	// Blocking provider (default ipdeny)
	if val, err := settings.GetSetting("geo_blocking_provider"); err == nil && val != "" {
		s.config.BlockingProvider = val
	} else {
		s.config.BlockingProvider = "ipdeny"
	}

	// Auto update
	if val, err := settings.GetSetting("geo_auto_update"); err == nil {
		s.config.AutoUpdate, _ = strconv.ParseBool(val)
	}

	// Update hour
	if val, err := settings.GetSetting("geo_update_hour"); err == nil {
		s.config.UpdateHour, _ = strconv.Atoi(val)
	} else {
		s.config.UpdateHour = 3 // Default 3 AM
	}

	// Update services
	if val, err := settings.GetSetting("geo_update_services"); err == nil && val != "" {
		s.config.UpdateServices = val
	} else {
		s.config.UpdateServices = "all"
	}

	// MaxMind license key (encrypted)
	if val, err := settings.GetSettingEncrypted("geo_maxmind_license_key"); err == nil {
		s.config.MaxMindLicenseKey = val
	}

	// IP2Location token (encrypted)
	if val, err := settings.GetSettingEncrypted("geo_ip2location_token"); err == nil {
		s.config.IP2LocationToken = val
	}

	// IP2Location variant
	if val, err := settings.GetSetting("geo_ip2location_variant"); err == nil && val != "" {
		s.config.IP2LocationVariant = val
	} else {
		s.config.IP2LocationVariant = "DB1"
	}

	s.config.DataDir = s.dataDir
}

// initProviders initializes the lookup and blocking providers
func (s *Service) initProviders() error {
	var lastErr error

	// Initialize lookup provider based on config
	switch s.config.LookupProvider {
	case "maxmind":
		provider := NewMaxMindProvider(filepath.Join(s.dataDir, "maxmind"), s.config.MaxMindLicenseKey)
		if err := provider.Init(); err != nil {
			log.Printf("Warning: MaxMind provider init failed: %v", err)
			lastErr = err
		} else {
			s.lookupProvider = provider
		}
	case "ip2location":
		// Get templates from provider config
		var fileCodeTemplate, fileNameTemplate string
		if cfg, ok := s.providersConfig.Providers["ip2location"]; ok {
			fileCodeTemplate = cfg.FileCodeTemplate
			fileNameTemplate = cfg.FileNameTemplate
		}
		provider := NewIP2LocationProvider(
			filepath.Join(s.dataDir, "ip2location"),
			s.config.IP2LocationToken,
			s.config.IP2LocationVariant,
			fileCodeTemplate,
			fileNameTemplate,
		)
		if err := provider.Init(); err != nil {
			log.Printf("Warning: IP2Location provider init failed: %v", err)
			lastErr = err
		} else {
			s.lookupProvider = provider
		}
	default:
		// No lookup provider
		s.lookupProvider = nil
	}

	// Initialize blocking provider (ipdeny)
	if s.config.BlockingEnabled {
		provider := NewIPDenyProvider(s.db)
		s.blockingProvider = provider
	}

	return lastErr
}

// migrateOldSettings migrates old firewall zone settings
func (s *Service) migrateOldSettings() {
	if s.db == nil {
		return
	}

	// Check if old settings exist
	var oldEnabled, oldHour string
	if err := s.db.QueryRow("SELECT value FROM settings WHERE key = 'zone_update_enabled'").Scan(&oldEnabled); err == nil {
		// Migrate zone_update_enabled -> geo_auto_update
		if _, err := settings.GetSetting("geo_auto_update"); err != nil {
			settings.SetSetting("geo_auto_update", oldEnabled)
			// Also enable blocking if zone updates were enabled
			if enabled, _ := strconv.ParseBool(oldEnabled); enabled {
				settings.SetSetting("geo_blocking_enabled", "true")
			}
		}
		// Delete old setting
		s.db.Exec("DELETE FROM settings WHERE key = 'zone_update_enabled'")
		log.Printf("Migrated zone_update_enabled -> geo_auto_update")
	}

	if err := s.db.QueryRow("SELECT value FROM settings WHERE key = 'zone_update_hour'").Scan(&oldHour); err == nil {
		// Migrate zone_update_hour -> geo_update_hour
		if _, err := settings.GetSetting("geo_update_hour"); err != nil {
			settings.SetSetting("geo_update_hour", oldHour)
		}
		// Delete old setting
		s.db.Exec("DELETE FROM settings WHERE key = 'zone_update_hour'")
		log.Printf("Migrated zone_update_hour -> geo_update_hour")
	}

	// Reload config after migration
	s.loadConfig()
}

// Handlers returns the HTTP handlers for this service
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		// Settings
		"GetSettings":    s.handleGetSettings,
		"UpdateSettings": s.handleUpdateSettings,
		// Lookups
		"LookupIP":   s.handleLookupIP,
		"LookupBulk": s.handleLookupBulk,
		// Status and data
		"GetStatus":     s.handleGetStatus,
		"TriggerUpdate": s.handleTriggerUpdate,
		"GetCountries":  s.handleGetCountries,
		// Zone management
		"RefreshZones": s.handleRefreshZones,
	}
}

// Shutdown gracefully shuts down the service
func (s *Service) Shutdown() {
	s.cancel()

	if s.lookupProvider != nil {
		s.lookupProvider.Close()
	}
	if s.blockingProvider != nil {
		s.blockingProvider.Close()
	}

	log.Println("Geolocation service shutdown complete")
}

// IsBlockingEnabled returns whether country blocking is enabled
func (s *Service) IsBlockingEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.BlockingEnabled
}

// FetchAndCacheCountryZones fetches zones from ipdeny if not cached, returns range count
func (s *Service) FetchAndCacheCountryZones(countryCode string) (int, error) {
	if s.blockingProvider == nil {
		return 0, fmt.Errorf("blocking provider not available")
	}

	countryCode = strings.ToUpper(countryCode)

	// Check if already cached
	zones, err := s.blockingProvider.GetCachedZones(countryCode)
	if err == nil && zones != "" {
		return strings.Count(zones, "\n") + 1, nil
	}

	// Fetch from ipdeny.com
	zones, err = s.blockingProvider.FetchCountryZones(countryCode)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch zones for %s: %w", countryCode, err)
	}

	// Cache zones
	if provider, ok := s.blockingProvider.(*IPDenyProvider); ok {
		if err := provider.CacheZones(countryCode, zones); err != nil {
			return 0, fmt.Errorf("failed to cache zones for %s: %w", countryCode, err)
		}
	}

	rangeCount := strings.Count(zones, "\n") + 1
	log.Printf("geolocation: fetched and cached %d ranges for country %s", rangeCount, countryCode)
	return rangeCount, nil
}

// GetAllBlockedCIDRs returns all blocked country CIDRs (implements nftables.CountryZonesProvider)
func (s *Service) GetAllBlockedCIDRs(outboundOnly bool) ([]string, error) {
	if s.blockingProvider == nil {
		return nil, fmt.Errorf("blocking provider not available")
	}
	return s.blockingProvider.GetAllBlockedCIDRs(outboundOnly)
}

// ReloadConfig reloads configuration and reinitializes providers
func (s *Service) ReloadConfig() error {
	s.loadConfig()
	return s.initProviders()
}

// EnableBlocking enables country blocking and triggers nftables apply
func (s *Service) EnableBlocking() {
	s.mu.Lock()
	s.config.BlockingEnabled = true
	s.mu.Unlock()

	// Initialize blocking provider if needed
	if s.blockingProvider == nil {
		s.blockingProvider = NewIPDenyProvider(s.db)
	}

	// Trigger nftables apply
	if s.nft != nil {
		s.nft.RequestApply()
	}
}

// DisableBlocking disables country blocking and triggers nftables apply
func (s *Service) DisableBlocking() {
	s.mu.Lock()
	s.config.BlockingEnabled = false
	s.mu.Unlock()

	// Trigger nftables apply (will result in empty country sets)
	if s.nft != nil {
		s.nft.RequestApply()
	}
}
