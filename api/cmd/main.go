package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"api/internal/adguard"
	"api/internal/auth"
	"api/internal/auth/pwa"
	"api/internal/config"
	"api/internal/database"
	"api/internal/docker"
	"api/internal/domains"
	"api/internal/events"
	"api/internal/firewall"
	"api/internal/fleet"
	"api/internal/geolocation"
	"api/internal/headscale"
	"api/internal/helper"
	"api/internal/logs"
	"api/internal/logs/sources"
	"api/internal/nftables"
	"api/internal/router"
	"api/internal/server"
	"api/internal/settings"
	"api/internal/setup"
	"api/internal/stats"
	"api/internal/traefik"
	"api/internal/turbotunnels"
	"api/internal/vpn"
	"api/internal/wireguard"
	"api/internal/ws"
)

func main() {
	// Initialize stats (records start time for uptime)
	stats.Init()

	// Load endpoint configuration
	configPath := helper.GetEnv("CONFIG_PATH")
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Loaded configuration v%s with %d services", cfg.Version, len(cfg.Services))

	// Create router
	r := router.New(cfg)

	// Data directory for persistent storage
	dataDir := helper.GetEnv("DATA_DIR")

	// Initialize shared database
	if _, err := database.Init(dataDir); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize encryption (must be before services that use encryption)
	helper.InitEncryption()

	// Keep the Cloudflare edge-range list current so CF-Connecting-IP is trusted
	// only for requests that genuinely transit Cloudflare (falls back to the
	// bundled list if the refresh fails).
	helper.StartCloudflareIPUpdater(context.Background())

	// Initialize and register services
	// Auth must be first (other services depend on it)
	if config.IsServiceEnabled("auth") {
		authSvc, err := auth.New()
		if err != nil {
			log.Printf("Warning: Failed to initialize auth service: %v", err)
		} else {
			auth.SetService(authSvc) // Store instance for other packages
			authSvc.Start()          // Start background cleanup
			r.RegisterService("auth", authSvc.Handlers())

			// Register auth validator for middleware
			router.SetAuthValidator(func(token string) bool {
				_, err := authSvc.ValidateSession(token)
				return err == nil
			})

			log.Println("Auth service registered")
		}
	}

	// Initialize PWA service (depends on auth)
	if config.IsServiceEnabled("pwa") {
		if auth.GetService() != nil {
			if pwaSvc, err := pwa.Init(); err != nil {
				log.Printf("Warning: Failed to initialize PWA service: %v", err)
			} else {
				r.RegisterService("pwa", pwaSvc.Handlers())
				log.Println("PWA service registered")
			}
		}
	}

	// Setup service (depends on auth for encryption)
	if config.IsServiceEnabled("setup") {
		setupSvc := setup.New()
		r.RegisterService("setup", setupSvc.Handlers())
		log.Println("Setup service registered")
	}

	// Events service: cross-subsystem activity feed (always on — cheap, no deps)
	r.RegisterService("events", events.New().Handlers())
	log.Println("Events service registered")

	// Settings service (depends on auth for encryption)
	if config.IsServiceEnabled("settings") {
		settingsSvc := settings.New()
		r.RegisterService("settings", settingsSvc.Handlers())
		log.Println("Settings service registered")

		// Set up Headscale config provider for helper package
		helper.SetHeadscaleConfigProvider(func() (*helper.HeadscaleConfig, error) {
			url, err := settings.GetSetting("headscale_api_url")
			if err != nil {
				return nil, err
			}
			apiKey, err := settings.GetSettingEncrypted("headscale_api_key")
			if err != nil {
				return nil, err
			}
			return &helper.HeadscaleConfig{
				URL:    helper.NormalizeHeadscaleURL(url),
				APIKey: apiKey,
			}, nil
		})
	}

	// Geolocation service (must be before firewall, as firewall depends on it)
	if config.IsServiceEnabled("geolocation") {
		geoSvc, err := geolocation.New(dataDir + "/geolocation")
		if err != nil {
			log.Printf("Warning: Failed to initialize geolocation service: %v", err)
		} else {
			geolocation.SetService(geoSvc)
			r.RegisterService("geolocation", geoSvc.Handlers())

			// Wire up settings callbacks for geolocation
			settings.GetGeoSettings = func() interface{} { return geoSvc.GetSettings() }
			settings.GetGeoStatus = func() interface{} { return geoSvc.GetStatus() }

			log.Println("Geolocation service registered")
		}
	}

	// Initialize nftables service (used by firewall and VPN ACL)
	nftSvc, err := nftables.New()
	if err != nil {
		log.Printf("Warning: Failed to initialize nftables service: %v", err)
	} else {
		// Set WebSocket broadcast function
		nftSvc.SetBroadcastFunc(ws.Broadcast)

		// Register VPN ACL table
		db, _ := database.GetDB()
		nftSvc.RegisterTable(nftables.NewVPNACLTable(db))

		log.Println("nftables service initialized")
	}

	var fwSvc *firewall.Service
	if config.IsServiceEnabled("firewall") {
		svc, err := firewall.New(dataDir, nftSvc)
		if err != nil {
			log.Printf("Warning: Failed to initialize firewall service: %v", err)
		} else {
			fwSvc = svc
			r.RegisterService("firewall", fwSvc.Handlers())
			log.Println("Firewall service registered")
		}
	}

	if config.IsServiceEnabled("wireguard") {
		wgSvc, err := wireguard.New(dataDir + "/wireguard")
		if err != nil {
			log.Printf("Warning: Failed to initialize wireguard service: %v", err)
		} else {
			wireguard.SetService(wgSvc) // Store instance for other packages
			r.RegisterService("wireguard", wgSvc.Handlers())
			log.Println("WireGuard service registered")
		}
	}

	var traefikSvc *traefik.Service
	if config.IsServiceEnabled("traefik") {
		traefikSvc = traefik.New()
		r.RegisterService("traefik", traefikSvc.Handlers())

		// Wire up settings callbacks for traefik
		settings.GetTraefikConfig = func() interface{} { return traefikSvc.GetConfig() }
		settings.GetTraefikVPNOnly = traefikSvc.GetVPNOnlyMode

		// Wire up VPN-only mode persistence (settings imports traefik transitively,
		// so traefik can't import settings — dependency inversion via function vars).
		traefik.PersistVPNOnlyMode = func(mode string) error {
			return settings.SetSetting("vpn_only_mode", mode)
		}
		traefik.LoadVPNOnlyMode = func() (string, error) {
			return settings.GetSetting("vpn_only_mode")
		}

		// L7 firewall-block toggle persistence (same dependency-inversion pattern).
		traefik.PersistFWBlock = settings.SetTraefikFWBlock
		traefik.LoadFWBlock = func() (bool, error) { return settings.GetTraefikFWBlock(), nil }

		// Re-apply the persisted VPN-only mode. Needed after manage.sh regenerates
		// core.yml from template (which wipes any middleware the user previously
		// attached via the UI toggle).
		traefikSvc.RestoreVPNOnlyMode()

		log.Println("Traefik service registered")
	}

	if config.IsServiceEnabled("headscale") {
		headscaleSvc := headscale.New()
		r.RegisterService("headscale", headscaleSvc.Handlers())
		log.Println("Headscale service registered")
	}

	if config.IsServiceEnabled("adguard") {
		adguardSvc := adguard.New()
		r.RegisterService("adguard", adguardSvc.Handlers())

		// Wire up credentials provider to get from settings
		adguard.CredentialsProvider = func() (string, string) {
			u, _ := settings.GetSetting("adguard_username")
			p, _ := settings.GetSettingEncrypted("adguard_password")
			return u, p
		}

		// First-boot bootstrap: manage.sh writes plaintext password to this
		// file so we can encrypt it into the settings DB, then delete it.
		bootstrapAdGuardPasswordFromFile("/adguard/.password.bootstrap")

		log.Println("AdGuard service registered")
	}

	var dockerSvc *docker.Service
	if config.IsServiceEnabled("docker") {
		dockerSvc = docker.New()
		r.RegisterService("docker", dockerSvc.Handlers())
		log.Println("Docker service registered")
	}

	var vpnSvc *vpn.Service
	if config.IsServiceEnabled("vpn") {
		vpnSvc = vpn.New()
		r.RegisterService("vpn", vpnSvc.Handlers())

		// Wire up settings callback for VPN router status
		settings.GetVPNRouterStatus = func() interface{} {
			status := vpn.GetRouterStatus()
			return &status
		}

		// Start traffic sync goroutine
		vpn.StartTrafficSync()

		log.Println("VPN ACL service registered")
	}

	if config.IsServiceEnabled("domains") {
		domainsSvc := domains.New()
		// Wire the L7 firewall-block toggle (hook avoids a domains -> settings import cycle).
		domains.FWBlockEnabled = settings.GetTraefikFWBlock
		r.RegisterService("domains", domainsSvc.Handlers())

		// Now that domains can regenerate routes, let the traefik toggle drive it, and
		// reconcile the block middleware to the persisted setting (survives core.yml regen).
		if traefikSvc != nil {
			traefik.RegenerateDomains = domains.ApplyRoutes
			traefikSvc.RestoreFWBlock(settings.GetTraefikFWBlock())
		}
		log.Println("Domains service registered")
	}

	if config.IsServiceEnabled("turbotunnels") {
		ttSvc := turbotunnels.New()
		r.RegisterService("turbotunnels", ttSvc.Handlers())
		// Public rotation trigger at /api/restart/{key} (bypasses session auth).
		r.RegisterService("rotate", ttSvc.RotateHandlers())
		// Public webhook trigger at /api/hook/{keys...} (bypasses session auth).
		r.RegisterService("webhook", ttSvc.WebhookHandlers())
		// Mirror the proxy's log markers: auth failures → the firewall jail
		// file (ban brute-forcers), authenticated connections → the logs table
		// (shown on the Logs page).
		turbotunnels.StartLogStreamer(context.Background())
		// Evict expired rotation abuse-guard entries so the in-memory maps stay bounded.
		turbotunnels.StartRotateGuardCleanup(context.Background())
		log.Println("Turbotunnels service registered")
	}

	if config.IsServiceEnabled("logs") {
		logsSvc, err := logs.New()
		if err != nil {
			log.Printf("Warning: Failed to initialize logs service: %v", err)
		} else {
			// Register watchers
			logsSvc.RegisterWatcher("traefik", sources.NewTraefikWatcher(logsSvc.GetDB(), logsSvc.GetConfig()))
			logsSvc.RegisterWatcher("adguard", sources.NewAdGuardWatcher(logsSvc.GetDB(), logsSvc.GetConfig()))
			logsSvc.RegisterWatcher("outbound", sources.NewOutboundWatcher(logsSvc.GetDB(), logsSvc.GetConfig()))
			logsSvc.RegisterWatcher("conntrack", sources.NewConntrackWatcher(logsSvc.GetDB(), logsSvc.GetConfig()))
			logsSvc.Start()
			r.RegisterService("logs", logsSvc.Handlers())
			log.Println("Logs service registered")
		}
	}

	// Host-security ("Server" page): read-only host telemetry. Uses the same host
	// access the container already has (network_mode:host, pid:host, /var/log:ro).
	if config.IsServiceEnabled("server") {
		if srvDB, dberr := database.GetDB(); dberr == nil {
			srvSvc := server.New(srvDB.DB)
			srvSvc.Certs = func() []server.CertInfo {
				certs, err := traefik.GetCertificates()
				if err != nil {
					return nil
				}
				out := make([]server.CertInfo, 0, len(certs))
				for _, c := range certs {
					out = append(out, server.CertInfo{Domain: c.Domain, DaysLeft: c.DaysLeft, Status: c.Status})
				}
				return out
			}
			srvSvc.GeoLookup = func(ip string) (string, string) {
				if g := geolocation.GetService(); g != nil {
					if res, lerr := g.LookupIP(ip); lerr == nil && res != nil {
						return res.ASName, res.CountryCode
					}
				}
				return "", ""
			}
			r.RegisterService("server", srvSvc.Handlers())
			log.Println("Server security service registered")
		}
	}

	// Fleet (Phase 2): panel-side CA + agent enrollment + machine registry + a
	// managed mTLS listener. On/off + port come from Settings (fleet_enabled /
	// fleet_port), NOT env. When enabled it auto-opens its port through the firewall
	// (reusing the allowed-ports mechanism) and auto-detects its own IPs for the cert.
	if config.IsServiceEnabled("fleet") {
		if flDB, dberr := database.GetDB(); dberr == nil {
			db := flDB.DB
			// Open/close the fleet port via the firewall's allowed-ports table, then
			// re-apply nftables — the same path essential ports use.
			openPort := func(port int) error {
				if fwSvc == nil {
					return nil
				}
				_, err := db.Exec(`INSERT OR IGNORE INTO firewall_entries
					(entry_type, value, action, direction, protocol, source, name, essential, enabled)
					VALUES ('port', ?, 'allow', 'inbound', 'tcp', 'system', 'wgscout-fleet', 1, 1)`,
					strconv.Itoa(port))
				fwSvc.RequestApply()
				return err
			}
			closePort := func(port int) error {
				if fwSvc == nil {
					return nil
				}
				_, err := db.Exec(`DELETE FROM firewall_entries WHERE entry_type='port' AND name='wgscout-fleet' AND value=?`,
					strconv.Itoa(port))
				fwSvc.RequestApply()
				return err
			}
			sslDomain := helper.GetEnvOptional("SSL_DOMAIN", "")
			installURL := helper.GetEnvOptional("FLEET_INSTALL_URL", "")
			// Source the panel's explicit blocklist for the "push blocks" command.
			blockedIPs := func() []string {
				if fwSvc == nil {
					return nil
				}
				return fwSvc.ExplicitBlockedCIDRs()
			}
			flSvc, ferr := fleet.New(db, installURL, sslDomain, openPort, closePort, blockedIPs)
			if ferr != nil {
				log.Printf("Fleet init failed: %v", ferr)
			} else {
				r.RegisterService("fleet", flSvc.Handlers())
				flSvc.ReloadFromSettings() // start the listener if enabled in Settings
				log.Printf("Fleet service registered (CA %s)", flSvc.CA().Fingerprint())
			}
		}
	}

	// Initialize WebSocket service
	wsSvc := ws.New()
	stats.SetWsClientsProvider(ws.ClientCount)
	log.Println("WebSocket service initialized")

	// Set up node status checker for real-time updates
	if vpnSvc != nil {
		ws.SetNodeStatsProvider(
			func() { vpnSvc.SyncClients() },
			vpn.GetNodeStats,
			vpn.GetNodeStatusList,
		)
	}

	// Set up overview stats provider for dashboard
	ws.SetOverviewStatsProvider(func() ws.OverviewStats {
		// Get system stats
		sysStats := stats.GetSystemStats()

		// Get traffic stats
		totalTx, totalRx, _ := vpn.GetTrafficTotals()
		rateTx, rateRx := vpn.GetTrafficRates()
		peerStats, _ := vpn.GetPeerTrafficStats()

		// Convert peer stats
		peers := make([]ws.PeerTrafficInfo, len(peerStats))
		for i, p := range peerStats {
			peers[i] = ws.PeerTrafficInfo{
				Name: p.Name,
				IP:   p.IP,
				Tx:   p.Tx,
				Rx:   p.Rx,
			}
		}

		// Get node stats
		nodeStats := vpn.GetNodeStats()

		// Get docker stats (if available, uses cache)
		var dockerInfo *docker.DockerInfo
		var diskUsage *docker.DiskUsage
		if dockerSvc != nil {
			dockerInfo, diskUsage = dockerSvc.GetOverviewStats()
		}

		// Assemble core-service health for the dashboard health row. Container-based
		// services report "up" when running; WireGuard runs on the host, so it's
		// checked via its interface. Profile-gated add-ons (turbotunnels) are only
		// listed when actually deployed, so a stopped optional add-on isn't
		// misreported as "down".
		upDown := func(ok bool) string {
			if ok {
				return "up"
			}
			return "down"
		}
		services := []ws.ServiceHealth{
			{Key: "wireguard", Name: "WireGuard", Status: upDown(vpn.WireGuardUp())},
		}
		if dockerSvc != nil {
			running := map[string]bool{}
			present := map[string]bool{}
			// Cached, non-blocking: this runs on the broadcast hot path.
			for _, c := range dockerSvc.GetContainersCached() {
				name := strings.TrimPrefix(c.Name, "/")
				present[name] = true
				running[name] = c.State == "running"
			}
			for _, svc := range []struct{ key, name, container string }{
				{"traefik", "Traefik", "traefik"},
				{"headscale", "Headscale", "headscale"},
				{"adguard", "AdGuard", "adguard"},
			} {
				services = append(services, ws.ServiceHealth{Key: svc.key, Name: svc.name, Status: upDown(running[svc.container])})
			}
			if present["turbotunnels"] {
				services = append(services, ws.ServiceHealth{Key: "turbotunnels", Name: "Tunnels", Status: upDown(running["turbotunnels"])})
			}
		}

		// Last-hour security summary for the Overview widgets (cached 30s inside).
		var security *ws.SecurityStats
		if fwSvc != nil {
			security = fwSvc.DashboardSecurity()
		}

		return ws.OverviewStats{
			System: ws.SystemStats{
				Uptime:       sysStats.Uptime,
				MemAlloc:     sysStats.MemAlloc,
				MemSys:       sysStats.MemSys,
				NumGoroutine: sysStats.NumGoroutine,
				NumGC:        sysStats.NumGC,
				WsClients:    sysStats.WsClients,
			},
			Traffic: ws.TrafficStats{
				TotalTx: totalTx,
				TotalRx: totalRx,
				RateTx:  rateTx,
				RateRx:  rateRx,
				ByPeer:  peers,
			},
			Nodes: ws.NodeStats{
				Online:  nodeStats.Online,
				Offline: nodeStats.Offline,
				HsNodes: nodeStats.HsNodes,
				WgPeers: nodeStats.WgPeers,
			},
			Services:   services,
			DockerInfo: dockerInfo,
			DiskUsage:  diskUsage,
			Security:   security,
		}
	})

	// Set up docker provider for real-time container updates
	if dockerSvc != nil {
		// Cached, non-blocking: this runs on the broadcast hot path.
		ws.SetDockerProvider(func() []docker.Container {
			return dockerSvc.GetContainersCached()
		})

		// Set up docker log streamer
		ws.SetDockerLogStreamer(&dockerLogAdapter{svc: dockerSvc})
	}

	// Start status checker (checks both nodes and docker)
	wsCfg := config.GetWebSocketConfig()
	ws.StartStatusChecker(time.Duration(wsCfg.StatusCheckIntervalSec) * time.Second)

	// Build router
	handler := r.Build()

	// Add WebSocket endpoint (needs special handling, not REST)
	mux := http.NewServeMux()
	mux.Handle("/api/ws", http.HandlerFunc(wsSvc.HandleWebSocket))

	// Internal-only block-list feed for the Traefik sentinel plugin (fetched container-to-
	// container over the Docker network, never routed by Traefik). Registered on the mux
	// directly so it bypasses the auth middleware; the handler refuses proxied requests.
	if fwSvc != nil {
		mux.Handle("/internal/blocklist", http.HandlerFunc(fwSvc.HandleInternalBlocklist))
		// Sentinel posts its periodic L7 block count here (internal-only, refuses proxied).
		mux.Handle("/internal/l7block", http.HandlerFunc(fwSvc.HandleInternalL7Block))
	}

	mux.Handle("/", handler)

	// Create server with timeouts
	port := helper.GetEnv("API_PORT")
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to signal shutdown completion
	done := make(chan bool, 1)

	// Handle shutdown signals
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigChan
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)

		// Create shutdown context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Stop accepting new connections and wait for existing ones
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error during server shutdown: %v", err)
		}

		// Stop WebSocket status checker
		ws.StopStatusChecker()

		// Stop VPN traffic sync
		vpn.StopTrafficSync()

		// Close database
		if err := database.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}

		log.Println("Graceful shutdown completed")
		done <- true
	}()

	// Start server
	log.Printf("Unified API server starting on port %s", port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	// Wait for shutdown to complete
	<-done
}

// dockerLogAdapter adapts docker.Service to ws.DockerLogStreamer interface
type dockerLogAdapter struct {
	svc *docker.Service
}

func (a *dockerLogAdapter) StreamLogs(containerName string, onLog func(ws.DockerLogEntry), stop <-chan struct{}) error {
	return a.svc.StreamLogs(containerName, func(entry docker.LogEntry) {
		onLog(ws.DockerLogEntry{
			Timestamp: entry.Timestamp,
			Message:   entry.Message,
			Stream:    entry.Stream,
		})
	}, stop)
}
