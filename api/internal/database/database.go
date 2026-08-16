package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ErrNotAvailable is returned when the database is not initialized
var ErrNotAvailable = errors.New("database not available")

// DefaultTimeout is the default query timeout
const DefaultTimeout = 30 * time.Second

// DB wraps sql.DB to automatically apply context timeouts to all queries
type DB struct {
	*sql.DB
	timeout time.Duration
}

// Query executes a query (uses embedded sql.DB directly for SQLite compatibility)
func (d *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return d.DB.Query(query, args...)
}

// Exec executes a statement with automatic timeout
func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	return d.DB.ExecContext(ctx, query, args...)
}

// QueryRow executes a query that returns a single row (uses embedded sql.DB directly)
func (d *DB) QueryRow(query string, args ...any) *sql.Row {
	return d.DB.QueryRow(query, args...)
}

// Begin starts a transaction (uses underlying sql.DB directly)
func (d *DB) Begin() (*sql.Tx, error) {
	return d.DB.Begin()
}

// instance is the shared database wrapper
var (
	instance  *sql.DB
	dbWrapper *DB
	once      sync.Once
	dbPath    string
	// initErr is package-level (not local) so a repeat Init after a failed first init
	// returns the recorded failure instead of (nil DB, nil error) — once.Do never re-runs.
	initErr error
)

// Init initializes the shared database connection
// Database file persists in Docker volume - survives container restarts
func Init(dataDir string) (*DB, error) {
	once.Do(func() {
		dbPath = dataDir + "/app.db"

		// Open database (creates file if not exists). _foreign_keys=1 enables FK
		// enforcement on every pooled connection, so the schema's ON DELETE CASCADE /
		// SET NULL actually fire (SQLite ignores foreign keys per-connection otherwise) —
		// e.g. deleting a peer now removes its virtual IPs + ACL rows instead of orphaning
		// them into the firewall.
		db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=1")
		if err != nil {
			initErr = fmt.Errorf("failed to open database: %v", err)
			return
		}

		// Create tables if they don't exist
		if err := createSchema(db); err != nil {
			initErr = fmt.Errorf("failed to create schema: %v", err)
			return
		}

		// Pre-check: enabling FK enforcement doesn't retroactively validate existing rows,
		// so surface any pre-existing violation loudly instead of letting it silently break
		// a future write. (createSchema already swept known orphans.)
		if rows, err := db.Query(`PRAGMA foreign_key_check`); err == nil {
			n := 0
			for rows.Next() {
				var table, parent string
				var rowid sql.NullInt64
				var fkid int
				if rows.Scan(&table, &rowid, &parent, &fkid) == nil {
					log.Printf("WARNING: foreign-key violation after enabling FK enforcement: table=%s rowid=%v -> %s", table, rowid.Int64, parent)
					n++
				}
			}
			rows.Close()
			if n > 0 {
				log.Printf("WARNING: %d foreign-key violation(s) remain — inserts touching those parents may now fail", n)
			}
		}

		instance = db
		dbWrapper = &DB{DB: db, timeout: DefaultTimeout}
		log.Printf("Database initialized at %s", dbPath)
	})

	return dbWrapper, initErr
}

// Get returns the raw sql.DB instance (for backwards compatibility)
func Get() *sql.DB {
	return instance
}

// GetDB returns the wrapped database instance or an error if not initialized
func GetDB() (*DB, error) {
	if dbWrapper == nil {
		return nil, ErrNotAvailable
	}
	return dbWrapper, nil
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
		escalate_asn BOOLEAN DEFAULT 0,
		escalate_asn_threshold INTEGER DEFAULT 15,
		escalate_asn_window INTEGER DEFAULT 3600,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Country zones cache (IP ranges for country blocking)
	CREATE TABLE IF NOT EXISTS country_zones_cache (
		country_code TEXT PRIMARY KEY,
		zones TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Cached IPv4 CIDRs for blocked/allowed ASNs (expanded from the ASN DB once,
	-- then joined at firewall-build time — mirrors country_zones_cache).
	CREATE TABLE IF NOT EXISTS asn_zones_cache (
		asn INTEGER PRIMARY KEY,
		cidrs TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Unified firewall entries table (IPs, ranges, countries, ports)
	CREATE TABLE IF NOT EXISTS firewall_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entry_type TEXT NOT NULL CHECK(entry_type IN ('ip', 'range', 'country', 'asn', 'port')),
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
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_type_action_enabled ON firewall_entries(entry_type, action, enabled);

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

	-- Activity events: one chronological feed across all subsystems
	-- (blocks, peer changes, config edits, restarts…). Retention-capped by the
	-- events package so it cannot grow without bound.
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		type TEXT NOT NULL,
		severity TEXT NOT NULL DEFAULT 'info',
		subsystem TEXT NOT NULL DEFAULT '',
		message TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_events_id_desc ON events(id DESC);

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
		cert_resolver TEXT DEFAULT '',
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

	-- Virtual IPs: extra VPN /32s routed to a peer (client_id), mapped by a DNAT on
	-- that peer to a device on its LAN (e.g. a camera). restricted=1 means only the
	-- peers listed in vpn_virtual_ip_acl may reach it.
	CREATE TABLE IF NOT EXISTS vpn_virtual_ips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_id INTEGER NOT NULL,
		ip TEXT NOT NULL UNIQUE,
		label TEXT DEFAULT '',
		target_ip TEXT DEFAULT '',
		target_port INTEGER DEFAULT 0,
		restricted INTEGER NOT NULL DEFAULT 1,
		quarantine INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (client_id) REFERENCES vpn_clients(id) ON DELETE CASCADE
	);

	-- Which peers may reach a restricted virtual IP (empty = nobody until opted in).
	CREATE TABLE IF NOT EXISTS vpn_virtual_ip_acl (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		virtual_ip_id INTEGER NOT NULL,
		source_client_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (virtual_ip_id) REFERENCES vpn_virtual_ips(id) ON DELETE CASCADE,
		FOREIGN KEY (source_client_id) REFERENCES vpn_clients(id) ON DELETE CASCADE,
		UNIQUE(virtual_ip_id, source_client_id)
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

	-- Virtual IP indexes
	CREATE INDEX IF NOT EXISTS idx_vpn_virtual_ips_client ON vpn_virtual_ips(client_id);
	CREATE INDEX IF NOT EXISTS idx_vpn_virtual_ip_acl_vip ON vpn_virtual_ip_acl(virtual_ip_id);
	CREATE INDEX IF NOT EXISTS idx_vpn_virtual_ip_acl_src ON vpn_virtual_ip_acl(source_client_id);
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
		logs_type TEXT NOT NULL CHECK(logs_type IN ('outbound', 'inbound', 'dns', 'fw', 'proxy')),

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

	-- Per-peer, per-destination byte rollup (populated by the conntrack watcher).
	-- Answers "peer X sent/received N bytes to destination Y" over time buckets.
	CREATE TABLE IF NOT EXISTS traffic_usage (
		peer_ip       TEXT NOT NULL,
		dest_ip       TEXT NOT NULL,
		dest_port     INTEGER NOT NULL DEFAULT 0,
		protocol      TEXT,
		domain        TEXT,
		dest_country  TEXT,
		bytes_up      INTEGER NOT NULL DEFAULT 0,
		bytes_down    INTEGER NOT NULL DEFAULT 0,
		bucket        DATETIME NOT NULL,
		updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (peer_ip, dest_ip, dest_port, bucket)
	);
	CREATE INDEX IF NOT EXISTS idx_usage_peer ON traffic_usage(peer_ip, bucket DESC);
	CREATE INDEX IF NOT EXISTS idx_usage_bucket ON traffic_usage(bucket);
	`

	// Execute logs schema
	if _, err := db.Exec(logsSchema); err != nil {
		return fmt.Errorf("failed to create logs schema: %v", err)
	}

	// User PWA schema (push notifications, preferences, locations)
	userPWASchema := `
	-- Push notification subscriptions (Web Push API)
	CREATE TABLE IF NOT EXISTS users_push_subscriptions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		device_name TEXT DEFAULT '',
		endpoint TEXT UNIQUE NOT NULL,
		key_p256dh TEXT NOT NULL,
		key_auth TEXT NOT NULL,
		user_agent TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	-- Notification preferences per user (key-value design for extensibility)
	CREATE TABLE IF NOT EXISTS users_notification_preferences (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		pref_key TEXT NOT NULL,
		enabled BOOLEAN DEFAULT 1,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(user_id, pref_key)
	);

	-- Device locations (GPS tracking)
	CREATE TABLE IF NOT EXISTS users_device_locations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		device_name TEXT DEFAULT '',
		latitude REAL NOT NULL,
		longitude REAL NOT NULL,
		accuracy REAL,
		altitude REAL,
		heading REAL,
		speed REAL,
		recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	-- Indexes for efficient queries
	CREATE INDEX IF NOT EXISTS idx_users_push_subs_user ON users_push_subscriptions(user_id);
	CREATE INDEX IF NOT EXISTS idx_users_device_loc_user_time ON users_device_locations(user_id, recorded_at DESC);
	`

	// Execute user PWA schema
	if _, err := db.Exec(userPWASchema); err != nil {
		return fmt.Errorf("failed to create user PWA schema: %v", err)
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

	// Add block_internet column to vpn_clients if missing (per-peer WAN block)
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('vpn_clients') WHERE name = 'block_internet'`).Scan(&count)
	if err == nil && count == 0 {
		if _, err := db.Exec(`ALTER TABLE vpn_clients ADD COLUMN block_internet INTEGER DEFAULT 0`); err == nil {
			log.Printf("Migration: added block_internet column to vpn_clients")
		}
	}

	// Add sentinel_config column to domain_routes if missing (JSON config for per-domain sentinel middleware)
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('domain_routes') WHERE name = 'sentinel_config'`).Scan(&count)
	if err == nil && count == 0 {
		if _, err := db.Exec(`ALTER TABLE domain_routes ADD COLUMN sentinel_config TEXT DEFAULT ''`); err == nil {
			log.Printf("Migration: added sentinel_config column to domain_routes")
		}
	}

	// Add cert_resolver column to domain_routes if missing (optional override for TLS cert resolver name)
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('domain_routes') WHERE name = 'cert_resolver'`).Scan(&count)
	if err == nil && count == 0 {
		if _, err := db.Exec(`ALTER TABLE domain_routes ADD COLUMN cert_resolver TEXT DEFAULT ''`); err == nil {
			log.Printf("Migration: added cert_resolver column to domain_routes")
		}
	}

	// Add skip_cert_verify column to domain_routes if missing (skip TLS verification for HTTPS backends)
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('domain_routes') WHERE name = 'skip_cert_verify'`).Scan(&count)
	if err == nil && count == 0 {
		if _, err := db.Exec(`ALTER TABLE domain_routes ADD COLUMN skip_cert_verify BOOLEAN DEFAULT 0`); err == nil {
			log.Printf("Migration: added skip_cert_verify column to domain_routes")
		}
	}

	// Add escalate_asn columns to jails if missing (escalate a jail ban to the whole
	// ASN, with its own threshold/window since a provider is much broader than a /24).
	jailASNCols := []struct{ name, ddl string }{
		{"escalate_asn", `ALTER TABLE jails ADD COLUMN escalate_asn BOOLEAN DEFAULT 0`},
		{"escalate_asn_threshold", `ALTER TABLE jails ADD COLUMN escalate_asn_threshold INTEGER DEFAULT 15`},
		{"escalate_asn_window", `ALTER TABLE jails ADD COLUMN escalate_asn_window INTEGER DEFAULT 3600`},
	}
	for _, c := range jailASNCols {
		err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('jails') WHERE name = ?`, c.name).Scan(&count)
		if err == nil && count == 0 {
			if _, err := db.Exec(c.ddl); err == nil {
				log.Printf("Migration: added %s column to jails", c.name)
			}
		}
	}

	// Allow the 'asn' firewall entry type (provider blocking). SQLite can't ALTER a
	// CHECK constraint, so rebuild firewall_entries if it doesn't permit 'asn' yet.
	// Done in a transaction so the security-critical table is never left partial.
	var fwSQL string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='firewall_entries'`).Scan(&fwSQL); err == nil {
		if strings.Contains(fwSQL, "CHECK(entry_type IN") && !strings.Contains(fwSQL, "'asn'") {
			stmts := []string{
				`ALTER TABLE firewall_entries RENAME TO firewall_entries_old`,
				`CREATE TABLE firewall_entries (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					entry_type TEXT NOT NULL CHECK(entry_type IN ('ip', 'range', 'country', 'asn', 'port')),
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
				)`,
				// Enumerate columns explicitly: a positional SELECT * would silently
				// misalign if a future schema adds/reorders a column between the two tables.
				`INSERT INTO firewall_entries
					(id, entry_type, value, action, direction, protocol, source, reason, name, essential, expires_at, enabled, hit_count, created_at)
					SELECT id, entry_type, value, action, direction, protocol, source, reason, name, essential, expires_at, enabled, hit_count, created_at
					FROM firewall_entries_old`,
				`DROP TABLE firewall_entries_old`,
				`CREATE UNIQUE INDEX IF NOT EXISTS idx_firewall_entries_unique ON firewall_entries(entry_type, value, protocol)`,
				`CREATE INDEX IF NOT EXISTS idx_firewall_entries_type ON firewall_entries(entry_type)`,
				`CREATE INDEX IF NOT EXISTS idx_firewall_entries_enabled ON firewall_entries(enabled)`,
				`CREATE INDEX IF NOT EXISTS idx_firewall_entries_expires ON firewall_entries(expires_at)`,
				`CREATE INDEX IF NOT EXISTS idx_firewall_entries_source ON firewall_entries(source)`,
				`CREATE INDEX IF NOT EXISTS idx_firewall_entries_type_enabled_direction ON firewall_entries(entry_type, enabled, direction)`,
				`CREATE INDEX IF NOT EXISTS idx_firewall_entries_type_action_enabled ON firewall_entries(entry_type, action, enabled)`,
			}
			// A swallowed failure here means the firewall silently can't store 'asn'
			// entries and the rebuild is re-attempted every boot — so log every failure
			// path loudly (ERROR), not silently.
			if tx, err := db.Begin(); err == nil {
				ok := true
				for _, stmt := range stmts {
					if _, err := tx.Exec(stmt); err != nil {
						log.Printf("ERROR Migration: firewall_entries 'asn' rebuild failed (will retry next boot): %v", err)
						ok = false
						break
					}
				}
				if ok {
					if err := tx.Commit(); err != nil {
						log.Printf("ERROR Migration: firewall_entries 'asn' rebuild commit failed (will retry next boot): %v", err)
					} else {
						log.Printf("Migration: rebuilt firewall_entries to allow 'asn' type")
					}
				} else {
					tx.Rollback()
				}
			} else {
				log.Printf("ERROR Migration: could not begin firewall_entries 'asn' rebuild (will retry next boot): %v", err)
			}
		}
	}

	// Add target/quarantine columns to vpn_virtual_ips if missing (LAN device DNAT target + quarantine flag)
	vipCols := []struct{ name, ddl string }{
		{"target_ip", `ALTER TABLE vpn_virtual_ips ADD COLUMN target_ip TEXT DEFAULT ''`},
		{"target_port", `ALTER TABLE vpn_virtual_ips ADD COLUMN target_port INTEGER DEFAULT 0`},
		{"quarantine", `ALTER TABLE vpn_virtual_ips ADD COLUMN quarantine INTEGER NOT NULL DEFAULT 0`},
	}
	for _, c := range vipCols {
		err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('vpn_virtual_ips') WHERE name = ?`, c.name).Scan(&count)
		if err == nil && count == 0 {
			if _, err := db.Exec(c.ddl); err == nil {
				log.Printf("Migration: added %s column to vpn_virtual_ips", c.name)
			}
		}
	}

	// Enforce "a peer maps a device IP+port once" durably (race-proof) with a partial
	// unique index. Bare-routed vips (target_ip='') are exempt. Existing exact-duplicate
	// rows would make the index creation fail, so dedupe first — keep the lowest id in
	// each (client_id, target_ip, target_port) group. Deleting a duplicate also removes its
	// allow-list grants (FK cascade / the orphan sweep below), so LOG the count — this must
	// not be a silent, unauditable data change.
	if res, err := db.Exec(`DELETE FROM vpn_virtual_ips
		WHERE target_ip != '' AND id NOT IN (
			SELECT MIN(id) FROM vpn_virtual_ips WHERE target_ip != ''
			GROUP BY client_id, target_ip, target_port
		)`); err != nil {
		log.Printf("Migration: vip dedupe failed: %v", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("Migration: removed %d duplicate forwarding vip(s) (same peer+device+port); their allow-list grants were removed with them", n)
	}
	// One-time sweep of pre-existing orphans: peers deleted while FK enforcement was OFF
	// left vips (and, transitively, ACL rows) behind. Enabling FK doesn't remove them
	// retroactively, so clear them once here. Order: vips first (with FK on this cascades
	// their ACL rows), then mop up any ACL rows orphaned before FK was enabled.
	if _, err := db.Exec(`DELETE FROM vpn_virtual_ips WHERE client_id NOT IN (SELECT id FROM vpn_clients)`); err != nil {
		log.Printf("Migration: vip orphan (deleted-peer) cleanup failed: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM vpn_virtual_ip_acl WHERE virtual_ip_id NOT IN (SELECT id FROM vpn_virtual_ips)
		OR source_client_id NOT IN (SELECT id FROM vpn_clients)`); err != nil {
		log.Printf("Migration: vip orphan-ACL cleanup failed: %v", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_vip_peer_target
		ON vpn_virtual_ips(client_id, target_ip, target_port) WHERE target_ip != ''`); err != nil {
		log.Printf("Migration: vip unique index failed: %v", err)
	}

	// Allow the 'proxy' log type (turbotunnels connections). SQLite can't ALTER
	// a CHECK constraint, so rebuild the logs table if it doesn't permit it yet.
	// The table is capped by the logs cleanup job, so the copy is cheap.
	var logsSQL string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='logs'`).Scan(&logsSQL); err == nil {
		if strings.Contains(logsSQL, "CHECK(logs_type IN") && !strings.Contains(logsSQL, "'proxy'") {
			stmts := []string{
				`ALTER TABLE logs RENAME TO logs_old`,
				`CREATE TABLE logs (
					logs_id INTEGER PRIMARY KEY AUTOINCREMENT,
					logs_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					logs_type TEXT NOT NULL CHECK(logs_type IN ('outbound', 'inbound', 'dns', 'fw', 'proxy')),
					logs_src_ip TEXT NOT NULL,
					logs_src_country TEXT,
					logs_dest_ip TEXT,
					logs_dest_port INTEGER,
					logs_dest_country TEXT,
					logs_domain TEXT,
					logs_protocol TEXT,
					logs_status TEXT,
					logs_duration INTEGER,
					logs_bytes INTEGER,
					logs_cached INTEGER DEFAULT 0,
					logs_method TEXT,
					logs_path TEXT,
					logs_router TEXT,
					logs_service TEXT,
					logs_query_type TEXT,
					logs_upstream TEXT,
					logs_rule TEXT
				)`,
				// Enumerate columns explicitly (like the firewall_entries rebuild) so a
				// future column add/reorder can't silently misalign this positional copy.
				`INSERT INTO logs
					(logs_id, logs_timestamp, logs_type, logs_src_ip, logs_src_country, logs_dest_ip, logs_dest_port, logs_dest_country, logs_domain, logs_protocol, logs_status, logs_duration, logs_bytes, logs_cached, logs_method, logs_path, logs_router, logs_service, logs_query_type, logs_upstream, logs_rule)
					SELECT logs_id, logs_timestamp, logs_type, logs_src_ip, logs_src_country, logs_dest_ip, logs_dest_port, logs_dest_country, logs_domain, logs_protocol, logs_status, logs_duration, logs_bytes, logs_cached, logs_method, logs_path, logs_router, logs_service, logs_query_type, logs_upstream, logs_rule
					FROM logs_old`,
				`DROP TABLE logs_old`,
				`CREATE INDEX IF NOT EXISTS idx_logs_type_time ON logs(logs_type, logs_timestamp DESC)`,
				`CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(logs_src_ip, logs_timestamp DESC)`,
				`CREATE INDEX IF NOT EXISTS idx_logs_domain ON logs(logs_domain)`,
				`CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(logs_type, logs_status)`,
			}
			if tx, err := db.Begin(); err == nil {
				ok := true
				for _, stmt := range stmts {
					if _, err := tx.Exec(stmt); err != nil {
						log.Printf("Migration: logs 'proxy' type rebuild failed: %v", err)
						ok = false
						break
					}
				}
				if ok {
					if err := tx.Commit(); err == nil {
						log.Printf("Migration: rebuilt logs table to allow 'proxy' type")
					}
				} else {
					tx.Rollback()
				}
			}
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
