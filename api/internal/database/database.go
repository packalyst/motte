package database

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// ErrNotAvailable is returned when the database is not initialized
var ErrNotAvailable = errors.New("database not available")

// DB is the shared database instance
var (
	instance *sql.DB
	once     sync.Once
	dbPath   string
)

// Init initializes the shared database connection
// Database file persists in Docker volume - survives container restarts
func Init(dataDir string) (*sql.DB, error) {
	var initErr error

	once.Do(func() {
		dbPath = dataDir + "/app.db"

		// Open database (creates file if not exists)
		db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
		if err != nil {
			initErr = fmt.Errorf("failed to open database: %v", err)
			return
		}

		// Create tables if they don't exist
		if err := createSchema(db); err != nil {
			initErr = fmt.Errorf("failed to create schema: %v", err)
			return
		}

		instance = db
		log.Printf("Database initialized at %s", dbPath)
	})

	return instance, initErr
}

// Get returns the shared database instance (for backwards compatibility)
func Get() *sql.DB {
	return instance
}

// GetDB returns the shared database instance or an error if not initialized
func GetDB() (*sql.DB, error) {
	if instance == nil {
		return nil, ErrNotAvailable
	}
	return instance, nil
}

// createSchema creates all required tables (if they don't exist)
func createSchema(db *sql.DB) error {
	// Firewall schema - unified firewall_entries table + supporting tables
	firewallSchema := `
	-- Jail configurations for fail2ban-style blocking
	CREATE TABLE IF NOT EXISTS jails (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		enabled BOOLEAN DEFAULT 1,
		log_file TEXT,
		filter_regex TEXT,
		max_retry INTEGER DEFAULT 5,
		find_time INTEGER DEFAULT 600,
		ban_time INTEGER DEFAULT 2592000,
		port TEXT,
		action TEXT DEFAULT 'drop',
		last_log_pos INTEGER DEFAULT 0,
		escalate_enabled BOOLEAN DEFAULT 0,
		escalate_threshold INTEGER DEFAULT 3,
		escalate_window INTEGER DEFAULT 3600,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Country zones cache (IP ranges for country blocking)
	CREATE TABLE IF NOT EXISTS country_zones_cache (
		country_code TEXT PRIMARY KEY,
		zones TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Unified firewall entries table (IPs, ranges, countries, ports)
	CREATE TABLE IF NOT EXISTS firewall_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entry_type TEXT NOT NULL CHECK(entry_type IN ('ip', 'range', 'country', 'port')),
		value TEXT NOT NULL,
		action TEXT DEFAULT 'block' CHECK(action IN ('block', 'allow')),
		direction TEXT DEFAULT 'inbound' CHECK(direction IN ('inbound', 'outbound', 'both')),
		protocol TEXT DEFAULT 'both' CHECK(protocol IN ('tcp', 'udp', 'both')),
		source TEXT DEFAULT 'manual',
		reason TEXT,
		name TEXT,
		essential BOOLEAN DEFAULT 0,
		expires_at DATETIME,
		enabled BOOLEAN DEFAULT 1,
		hit_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Firewall entries indexes
	CREATE UNIQUE INDEX IF NOT EXISTS idx_firewall_entries_unique ON firewall_entries(entry_type, value, protocol);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_type ON firewall_entries(entry_type);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_enabled ON firewall_entries(enabled);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_expires ON firewall_entries(expires_at);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_source ON firewall_entries(source);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_type_enabled_direction ON firewall_entries(entry_type, enabled, direction);

	-- Country zones cache indexes
	CREATE INDEX IF NOT EXISTS idx_country_zones_code_updated ON country_zones_cache(country_code, updated_at);
	`

	// App schema - users, settings, sessions, domain routes
	appSchema := `
	-- Users table for authentication
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret_enc TEXT,
		totp_enabled INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	);

	-- Settings table (key-value store)
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT,
		encrypted BOOLEAN DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Sessions table for login tokens
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		ip_address TEXT DEFAULT '',
		user_agent TEXT DEFAULT '',
		last_active DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	-- Domain routes for Traefik reverse proxy
	CREATE TABLE IF NOT EXISTS domain_routes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE NOT NULL,
		target_ip TEXT NOT NULL,
		target_port INTEGER NOT NULL,
		vpn_client_id INTEGER,
		enabled BOOLEAN DEFAULT 1,
		https_backend BOOLEAN DEFAULT 0,
		middlewares TEXT DEFAULT '[]',
		description TEXT,
		access_mode TEXT DEFAULT 'vpn' CHECK(access_mode IN ('vpn', 'public')),
		frontend_ssl BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (vpn_client_id) REFERENCES vpn_clients(id) ON DELETE SET NULL
	);

	-- Sessions indexes
	CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_expires_lastactive ON sessions(user_id, expires_at, last_active DESC);

	-- Domain routes indexes
	CREATE INDEX IF NOT EXISTS idx_domain_routes_domain ON domain_routes(domain);
	CREATE INDEX IF NOT EXISTS idx_domain_routes_client ON domain_routes(vpn_client_id);
	CREATE INDEX IF NOT EXISTS idx_domain_routes_enabled_domain ON domain_routes(enabled, domain);
	CREATE INDEX IF NOT EXISTS idx_domain_routes_vpn_enabled ON domain_routes(vpn_client_id, enabled);
	`

	// VPN ACL tables - unified view of all VPN clients and access control
	vpnSchema := `
	-- Unified view of all VPN clients (WireGuard + Headscale)
	CREATE TABLE IF NOT EXISTS vpn_clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		ip TEXT NOT NULL UNIQUE,
		type TEXT NOT NULL CHECK(type IN ('wireguard', 'headscale')),
		external_id TEXT,
		raw_data TEXT,
		public_key TEXT,
		private_key_enc TEXT,
		preshared_key_enc TEXT,
		enabled INTEGER DEFAULT 1,
		acl_policy TEXT NOT NULL DEFAULT 'selected' CHECK(acl_policy IN ('block_all', 'selected', 'allow_all')),
		total_tx INTEGER DEFAULT 0,
		total_rx INTEGER DEFAULT 0,
		last_tx INTEGER DEFAULT 0,
		last_rx INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- ACL rules between clients (source can reach target)
	-- Only ONE entry per client pair (check both directions before insert)
	CREATE TABLE IF NOT EXISTS vpn_acl_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_client_id INTEGER NOT NULL,
		target_client_id INTEGER NOT NULL,
		bidirectional INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (source_client_id) REFERENCES vpn_clients(id) ON DELETE CASCADE,
		FOREIGN KEY (target_client_id) REFERENCES vpn_clients(id) ON DELETE CASCADE,
		UNIQUE(source_client_id, target_client_id)
	);

	-- VPN router status tracking
	CREATE TABLE IF NOT EXISTS vpn_router_config (
		id INTEGER PRIMARY KEY CHECK(id = 1),
		enabled BOOLEAN DEFAULT 0,
		authkey TEXT,
		headscale_user TEXT DEFAULT 'vpn-router',
		route_id TEXT,
		status TEXT DEFAULT 'disabled',
		last_check DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- VPN clients indexes
	CREATE INDEX IF NOT EXISTS idx_vpn_clients_type ON vpn_clients(type);
	CREATE INDEX IF NOT EXISTS idx_vpn_clients_external_id ON vpn_clients(external_id);

	-- VPN ACL rules indexes
	CREATE INDEX IF NOT EXISTS idx_vpn_acl_source ON vpn_acl_rules(source_client_id);
	CREATE INDEX IF NOT EXISTS idx_vpn_acl_target ON vpn_acl_rules(target_client_id);
	`

	// Execute firewall schema
	if _, err := db.Exec(firewallSchema); err != nil {
		return fmt.Errorf("failed to create firewall schema: %v", err)
	}

	// Execute app schema
	if _, err := db.Exec(appSchema); err != nil {
		return fmt.Errorf("failed to create app schema: %v", err)
	}

	// Execute VPN ACL schema
	if _, err := db.Exec(vpnSchema); err != nil {
		return fmt.Errorf("failed to create VPN schema: %v", err)
	}

	// Unified logs schema - outbound/inbound/dns
	logsSchema := `
	CREATE TABLE IF NOT EXISTS logs (
		logs_id INTEGER PRIMARY KEY AUTOINCREMENT,
		logs_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		logs_type TEXT NOT NULL CHECK(logs_type IN ('outbound', 'inbound', 'dns', 'fw')),

		-- Source
		logs_src_ip TEXT NOT NULL,
		logs_src_country TEXT,

		-- Destination
		logs_dest_ip TEXT,
		logs_dest_port INTEGER,
		logs_dest_country TEXT,

		-- Common
		logs_domain TEXT,
		logs_protocol TEXT,
		logs_status TEXT,
		logs_duration INTEGER,
		logs_bytes INTEGER,
		logs_cached INTEGER DEFAULT 0,

		-- Inbound extras
		logs_method TEXT,
		logs_path TEXT,
		logs_router TEXT,
		logs_service TEXT,

		-- DNS extras
		logs_query_type TEXT,
		logs_upstream TEXT,
		logs_rule TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_logs_type_time ON logs(logs_type, logs_timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(logs_src_ip, logs_timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_logs_domain ON logs(logs_domain);
	CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(logs_type, logs_status);
	`

	// Execute logs schema
	if _, err := db.Exec(logsSchema); err != nil {
		return fmt.Errorf("failed to create logs schema: %v", err)
	}

	// Run migrations for existing databases
	runMigrations(db)

	log.Printf("Database schema initialized")
	return nil
}

// runMigrations applies schema changes to existing databases
func runMigrations(db *sql.DB) {
	// Add bidirectional column to vpn_acl_rules if missing
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('vpn_acl_rules') WHERE name = 'bidirectional'`).Scan(&count)
	if err == nil && count == 0 {
		if _, err := db.Exec(`ALTER TABLE vpn_acl_rules ADD COLUMN bidirectional INTEGER DEFAULT 0`); err == nil {
			log.Printf("Migration: added bidirectional column to vpn_acl_rules")
		}
	}

	// Add traffic columns to vpn_clients if missing
	trafficCols := []string{"total_tx", "total_rx", "last_tx", "last_rx"}
	for _, col := range trafficCols {
		err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('vpn_clients') WHERE name = ?`, col).Scan(&count)
		if err == nil && count == 0 {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE vpn_clients ADD COLUMN %s INTEGER DEFAULT 0`, col)); err == nil {
				log.Printf("Migration: added %s column to vpn_clients", col)
			}
		}
	}

	// Add sentinel_config column to domain_routes if missing (JSON config for per-domain sentinel middleware)
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('domain_routes') WHERE name = 'sentinel_config'`).Scan(&count)
	if err == nil && count == 0 {
		if _, err := db.Exec(`ALTER TABLE domain_routes ADD COLUMN sentinel_config TEXT DEFAULT ''`); err == nil {
			log.Printf("Migration: added sentinel_config column to domain_routes")
		}
	}
}

// Close closes the database connection
func Close() error {
	if instance != nil {
		return instance.Close()
	}
	return nil
}
