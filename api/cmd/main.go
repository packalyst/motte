package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"api/internal/adguard"
	"api/internal/auth"
	"api/internal/config"
	"api/internal/database"
	"api/internal/docker"
	"api/internal/domains"
	"api/internal/firewall"
	"api/internal/geolocation"
	"api/internal/headscale"
	"api/internal/helper"
	"api/internal/logs"
	"api/internal/logs/sources"
	"api/internal/nftables"
	"api/internal/router"
	"api/internal/settings"
	"api/internal/setup"
	"api/internal/stats"
	"api/internal/traefik"
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

	// Setup service (depends on auth for encryption)
	if config.IsServiceEnabled("setup") {
		setupSvc := setup.New()
		r.RegisterService("setup", setupSvc.Handlers())
		log.Println("Setup service registered")
	}

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

	if config.IsServiceEnabled("firewall") {
		fwSvc, err := firewall.New(dataDir, nftSvc)
		if err != nil {
			log.Printf("Warning: Failed to initialize firewall service: %v", err)
		} else {
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

	if config.IsServiceEnabled("traefik") {
		traefikSvc := traefik.New()
		r.RegisterService("traefik", traefikSvc.Handlers())

		// Wire up settings callbacks for traefik
		settings.GetTraefikConfig = func() interface{} { return traefikSvc.GetConfig() }
		settings.GetTraefikVPNOnly = traefikSvc.GetVPNOnlyMode

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
		r.RegisterService("domains", domainsSvc.Handlers())
		log.Println("Domains service registered")
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
			logsSvc.Start()
			r.RegisterService("logs", logsSvc.Handlers())
			log.Println("Logs service registered")
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

		// Get docker stats (if available)
		var dockerInfo *docker.DockerInfo
		var diskUsage *docker.DiskUsage
		if dockerSvc != nil {
			dockerInfo, diskUsage = dockerSvc.GetOverviewStats()
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
			DockerInfo: dockerInfo,
			DiskUsage:  diskUsage,
		}
	})

	// Set up docker provider for real-time container updates
	if dockerSvc != nil {
		ws.SetDockerProvider(func() []docker.Container {
			containers, err := dockerSvc.GetContainers()
			if err != nil {
				return nil
			}
			return containers
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
