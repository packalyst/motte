package firewall

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"api/internal/config"
	"api/internal/database"
	"api/internal/geolocation"
	"api/internal/helper"
	"api/internal/nftables"
	"api/internal/router"
	"api/internal/ws"
)

func init() {
	LoadBlocklistSources()
}

// New creates a new firewall service
func New(dataDir string, nftSvc *nftables.Service) (*Service, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}

	fwCfg := config.GetFirewallConfig()
	ctx, cancel := context.WithCancel(context.Background())

	svc := &Service{
		db:           db,
		dnsCache:     newLRUDNSCache(dnsCacheMaxSize, dnsCacheTTL),
		blockCache:   &blockCache{ttl: 10 * time.Second},
		jailMonitors: make(map[int64]*jailMonitor),
		ctx:          ctx,
		cancel:       cancel,
		nft:          nftSvc,
		config: Config{
			EssentialPorts:         helper.BuildEssentialPorts(),
			IgnoreNetworks:         helper.ParseStringList(helper.GetEnv("IGNORE_NETWORKS")),
			MaxAttempts:            fwCfg.MaxAttempts,
			DataDir:                dataDir,
			WgPort:                 helper.GetEnvInt("WG_PORT"),
			WgIPPrefix:             helper.ExtractIPPrefix(helper.GetEnv("WG_IP_RANGE")),
			HeadscaleIPPrefix:      helper.ExtractIPPrefix(helper.GetEnv("HEADSCALE_IP_RANGE")),
			JailCheckInterval:      fwCfg.JailCheckIntervalSec,
			CleanupInterval:        fwCfg.CleanupIntervalMin,
			DNSLookupTimeout:       fwCfg.DNSLookupTimeoutSec,
			ServerIP:               helper.GetEnv("SERVER_IP"),
		},
	}

	// Get geolocation service for country zones
	geoSvc := geolocation.GetService()
	svc.geo = geoSvc

	// Give geo service access to nftables for triggering applies
	if geoSvc != nil {
		geoSvc.SetNftService(nftSvc)
	}

	// Register firewall table with nftables service
	firewallTable := nftables.NewFirewallTable(db, geoSvc)
	nftSvc.RegisterTable(firewallTable)

	// Ensure default jails exist
	if err := svc.ensureDefaultJails(); err != nil {
		log.Printf("Warning: Failed to ensure default jails: %v", err)
	}

	// Ensure essential ports are in firewall_entries
	if err := svc.ensureEssentialPorts(); err != nil {
		log.Printf("Warning: Failed to ensure essential ports: %v", err)
	}

	// Apply initial rules
	if err := svc.ApplyRules(); err != nil {
		log.Printf("Warning: Failed to apply initial firewall rules: %v", err)
	}

	// Start background tasks
	go svc.runJailMonitors()
	go svc.runExpirationCleanup()

	log.Printf("Firewall service initialized")
	return svc, nil
}

// ensureEssentialPorts adds essential ports to firewall_entries if not present
func (s *Service) ensureEssentialPorts() error {
	for _, ep := range s.config.EssentialPorts {
		_, err := s.db.Exec(`INSERT OR IGNORE INTO firewall_entries
			(entry_type, value, action, direction, protocol, source, name, essential, enabled)
			VALUES ('port', ?, 'allow', 'inbound', ?, 'system', ?, 1, 1)`,
			strconv.Itoa(ep.Port), ep.Protocol, ep.Service)
		if err != nil {
			return fmt.Errorf("failed to add essential port %d: %v", ep.Port, err)
		}
	}
	return nil
}

// RequestApply schedules a debounced apply via nftables service
func (s *Service) RequestApply() {
	if s.nft != nil {
		s.nft.RequestApply()
	}
}

// FetchCountryZonesAsync fetches zones for countries in background with WS progress
func (s *Service) FetchCountryZonesAsync(countries []string) {
	if len(countries) == 0 {
		s.RequestApply()
		return
	}

	go func() {
		total := len(countries)
		ws.Broadcast("general_info", map[string]interface{}{
			"event":   "firewall:zones:start",
			"total":   total,
			"current": 0,
		})

		for i, code := range countries {
			rangeCount := 0
			var errMsg string

			if s.geo != nil {
				count, err := s.geo.FetchAndCacheCountryZones(code)
				if err != nil {
					errMsg = err.Error()
					log.Printf("Warning: failed to fetch zones for %s: %v", code, err)
				} else {
					rangeCount = count
					// Update hit_count in DB
					s.db.Exec("UPDATE firewall_entries SET hit_count = ? WHERE entry_type = 'country' AND value = ?",
						rangeCount, code)
				}
			}

			ws.Broadcast("general_info", map[string]interface{}{
				"event":      "firewall:zones:progress",
				"total":      total,
				"current":    i + 1,
				"country":    code,
				"rangeCount": rangeCount,
				"error":      errMsg,
			})
		}

		ws.Broadcast("general_info", map[string]interface{}{
			"event": "firewall:zones:complete",
			"total": total,
		})

		s.RequestApply()
	}()
}

// ApplyRules applies firewall rules synchronously via nftables service
func (s *Service) ApplyRules() error {
	if s.nft == nil {
		return fmt.Errorf("nftables service not initialized")
	}
	return s.nft.ApplyAll()
}

// GetSyncStatus returns the sync status from nftables service
func (s *Service) GetSyncStatus() nftables.SyncStatus {
	if s.nft == nil {
		return nftables.SyncStatus{InSync: false, LastApplyError: "nftables service not initialized"}
	}
	return s.nft.GetSyncStatus()
}

// Stop stops the firewall service
func (s *Service) Stop() {
	s.cancel()
	if s.nft != nil {
		s.nft.Stop()
	}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		// Status and config
		"GetStatus":      s.handleStatus,
		"GetConfig":      s.handleGetConfig,
		"UpdateConfig":   s.handleUpdateConfig,
		"ApplyRules":     s.handleApplyRules,
		"SyncStatus":     s.handleSyncStatus,

		// Unified entries API
		"GetEntries":      s.handleGetEntries,
		"CreateEntry":     s.handleCreateEntry,
		"DeleteEntry":     s.handleDeleteEntry,
		"ToggleEntry":     s.handleToggleEntry,
		"BulkEntries":     s.handleBulkEntries,
		"ImportEntries":   s.handleImportEntries,
		"DeleteBySource":  s.handleDeleteBySource,
		"DeleteAll":       s.handleDeleteAll,

		// Legacy endpoints (ports, blocklists)
		"GetPorts":        s.handleGetPorts,
		"AddPort":         s.handleAddPort,
		"RemovePort":      s.handleRemovePort,
		"GetBlocklists":   s.handleGetBlocklists,

		// SSH port management
		"ChangeSSHPort": s.handleChangeSSHPort,

		// Jails (fail2ban)
		"GetJails":   s.handleGetJails,
		"CreateJail": s.handleCreateJail,
		"GetJail":    s.handleGetJail,
		"UpdateJail": s.handleUpdateJail,
		"DeleteJail": s.handleDeleteJail,
	}
}
