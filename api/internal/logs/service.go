package logs

import (
	"context"
	"log"
	"sync"
	"time"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"
)

// Service manages all log watchers
type Service struct {
	db       *database.DB
	config   Config
	watchers map[string]Watcher
	enabled  map[string]bool
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	wg       sync.WaitGroup
}

// New creates a new logs service
func New() (*Service, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	config := Config{
		TraefikLogPath:    helper.GetEnv("TRAEFIK_LOGS"),
		AdGuardLogPath:    helper.GetEnv("ADGUARD_LOGS"),
		KernLogPath:       helper.GetEnv("KERN_LOG"),
		WgIPPrefix:        helper.GetEnvOptional("WG_IP_PREFIX", "10.8.0."),
		HeadscaleIPPrefix: helper.GetEnvOptional("HEADSCALE_IP_PREFIX", "100.64."),
		MaxEntries:        helper.GetEnvInt("LOGS_MAX_ENTRIES"),
		CleanupInterval:   helper.GetEnvInt("LOGS_CLEANUP_INTERVAL"),
		CountryInterval:   helper.GetEnvInt("LOGS_COUNTRY_INTERVAL"),
		CountryBatchSize:  helper.GetEnvInt("LOGS_COUNTRY_BATCH"),
	}

	s := &Service{
		db:       db,
		config:   config,
		watchers: make(map[string]Watcher),
		enabled:  make(map[string]bool),
		ctx:      ctx,
		cancel:   cancel,
	}

	return s, nil
}

// RegisterWatcher registers a watcher by name (disabled by default)
func (s *Service) RegisterWatcher(name string, watcher Watcher) {
	s.watchers[name] = watcher
	s.enabled[name] = false // User enables in Settings
}

// GetDB returns the database connection for watcher creation
func (s *Service) GetDB() *database.DB {
	return s.db
}

// GetConfig returns the config for watcher creation
func (s *Service) GetConfig() Config {
	return s.config
}

// Start starts all enabled watchers and background jobs
func (s *Service) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, watcher := range s.watchers {
		if s.enabled[name] {
			s.startWatcher(name, watcher)
		}
	}

	// Start country updater
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runCountryUpdater()
	}()

	// Start cleanup job
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runCleanup()
	}()

	log.Printf("Logs service started")
}

// startWatcher starts a single watcher
func (s *Service) startWatcher(name string, watcher Watcher) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := watcher.Start(s.ctx); err != nil {
			log.Printf("Watcher %s error: %v", name, err)
		}
	}()
	log.Printf("Started watcher: %s", name)
}

// Stop stops all watchers and background jobs
func (s *Service) Stop() {
	s.cancel()
	s.wg.Wait()
	log.Printf("Logs service stopped")
}

// EnableWatcher enables/disables a watcher
func (s *Service) EnableWatcher(name string, enable bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	watcher, exists := s.watchers[name]
	if !exists {
		return false
	}

	s.enabled[name] = enable

	if enable && !watcher.IsRunning() {
		s.startWatcher(name, watcher)
	} else if !enable && watcher.IsRunning() {
		watcher.Stop()
		// Wait for watcher to fully stop (max 2 seconds)
		for i := 0; i < 20 && watcher.IsRunning(); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return true
}

// GetStatus returns status of all watchers
func (s *Service) GetStatus() []WatcherStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var statuses []WatcherStatus
	for name, watcher := range s.watchers {
		statuses = append(statuses, WatcherStatus{
			Name:      name,
			Enabled:   s.enabled[name],
			Running:   watcher.IsRunning(),
			LastError: watcher.LastError(),
			Processed: watcher.Processed(),
		})
	}
	return statuses
}

// Handlers returns API handlers map
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetLogs":    s.handleGetLogs,
		"GetStats":   s.handleGetStats,
		"GetStatus":  s.handleGetStatus,
		"SetWatcher": s.handleSetWatcher,
	}
}
