package fleet

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errBadPort = errors.New("invalid port")

// Service is the panel-side fleet subsystem: the CA, enrollment, the machine
// registry, the mTLS report/command channel, and a managed mTLS listener whose
// on/off + port come from Settings (no env vars). When enabled it also opens its
// port through the firewall (reusing the allowed-ports mechanism) and closes it
// when disabled.
type Service struct {
	db        *sql.DB
	ca        *CA
	sslDomain string // panel's public domain, if any (added to cert SANs + host options)

	// firewall port open/close callbacks (wired to the firewall service in main).
	openPort  func(port int) error
	closePort func(port int) error

	// blockedIPs returns the panel's explicit ip/range blocklist, so the operator can
	// push it onto a machine (sync-blocks). Nil ⇒ push is unavailable.
	blockedIPs func() []string

	// fwBlockEnabled reports the "Enforce Firewall on Proxied Traffic" setting, so the
	// generated /agent Traefik route carries sentinel_fw_block only when it's on. Nil ⇒ off.
	fwBlockEnabled func() bool

	// agentCache pulls the agent binary/manifest/installer from the latest GitHub release
	// and caches them on disk, so the repo ships no binaries.
	agentCache *agentCache

	// broadcast pushes a WS event to subscribed browsers (set to ws.Broadcast in main, nil
	// otherwise). Used to push a machine's report the instant it's ingested — so the UI
	// updates live instead of polling.
	broadcast func(channel string, payload any)

	mu      sync.Mutex
	enabled bool
	port    int
	srv     *http.Server

	// cfgMu serializes handleSetConfig so the migrating-check and the migration start are
	// one atomic step — two concurrent config POSTs must not both pass the check.
	cfgMu sync.Mutex

	// Live port migration (dual-listen grace window). When the port changes with agents
	// enrolled, the new listener starts while the old one (oldSrv/oldPort) stays up until
	// every agent acks set-panel-port or migrateEndsAt passes — so none are stranded.
	oldSrv        *http.Server
	oldPort       int
	migrating     bool
	migrateEndsAt time.Time
	migrateIDs    []string

	clientCertTTL time.Duration
}

// SetBroadcast wires the WS broadcast fn so report ingests push live to the UI.
func (s *Service) SetBroadcast(fn func(channel string, payload any)) { s.broadcast = fn }

// New initializes the schema + CA. The listener is NOT started here — call
// ReloadFromSettings() once the firewall callbacks are wired. openPort/closePort
// may be nil (then the firewall isn't touched).
func New(db *sql.DB, sslDomain string, openPort, closePort func(int) error, blockedIPs func() []string, fwBlockEnabled func() bool) (*Service, error) {
	if err := ensureSchema(db); err != nil {
		return nil, err
	}
	// Self-heal any child rows left behind by a machine that no longer exists (see
	// sweepOrphans). Reclaim the freed file space once if the cleanup was large.
	if removed := sweepOrphans(db); removed > 1000 {
		if _, err := db.Exec(`VACUUM`); err != nil {
			log.Printf("fleet: VACUUM after orphan sweep failed: %v", err)
		} else {
			log.Printf("fleet: VACUUM reclaimed space after removing %d orphan rows", removed)
		}
	}
	ca, err := loadOrCreateCA(db)
	if err != nil {
		return nil, err
	}
	return &Service{
		db:             db,
		ca:             ca,
		sslDomain:      sslDomain,
		openPort:       openPort,
		closePort:      closePort,
		blockedIPs:     blockedIPs,
		fwBlockEnabled: fwBlockEnabled,
		agentCache:     newAgentCache(),
		clientCertTTL:  90 * 24 * time.Hour,
	}, nil
}

// CA exposes the certificate authority (fingerprint / cert PEM for install commands).
func (s *Service) CA() *CA { return s.ca }

const (
	settingEnabled = "fleet_enabled"
	settingPort    = "fleet_port"
	// 9443: an alternate-HTTPS port free in this stack. NOT 8443 (that's DERP_HTTP_PORT)
	// nor 8080/8081/8085/9090/50443 (Traefik/api/headscale/metrics/grpc).
	defaultPort = 9443
)

// ReloadFromSettings reads fleet_enabled + fleet_port from the settings table and
// (re)applies the listener + firewall port. Called at startup and whenever the
// Settings page saves fleet config.
func (s *Service) ReloadFromSettings() {
	enabled := s.getSetting(settingEnabled) == "true"
	port := defaultPort
	if v := s.getSetting(settingPort); v != "" {
		if p, err := parsePort(v); err == nil {
			port = p
		}
	}
	s.applyConfig(enabled, port)
	if err := s.ApplyInstallRoute(); err != nil {
		log.Printf("fleet: install route apply: %v", err)
	}
}

// applyConfig starts/stops the listener and opens/closes the firewall port to match
// the desired state. Idempotent.
func (s *Service) applyConfig(enabled bool, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !enabled {
		if s.srv != nil {
			s.stopLocked()
		}
		return
	}
	// enabled: (re)start if not running or the port changed.
	if s.srv != nil && s.port == port {
		return
	}
	if s.srv != nil {
		s.closeListenerLocked(s.srv, s.port)
		s.srv = nil
	}
	s.startListenerLocked(port)
}

// startListenerLocked opens the firewall port and starts a new mTLS server on it,
// recording it as the current listener. Caller holds s.mu.
func (s *Service) startListenerLocked(port int) {
	if s.openPort != nil {
		if err := s.openPort(port); err != nil {
			log.Printf("fleet: could not open firewall port %d: %v", port, err)
		}
	}
	tc, err := s.tlsConfig()
	if err != nil {
		log.Printf("fleet: TLS config failed: %v", err)
		return
	}
	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           s.Handler(),
		TLSConfig:         tc,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.srv = srv
	s.enabled = true
	s.port = port
	go func() {
		log.Printf("fleet: mTLS listener on :%d (CA %s)", port, s.ca.Fingerprint())
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("fleet: listener on :%d stopped: %v", port, err)
		}
	}()
}

// closeListenerLocked shuts a specific server and closes its firewall port. Caller
// holds s.mu.
func (s *Service) closeListenerLocked(srv *http.Server, port int) {
	if srv != nil {
		_ = srv.Close()
		log.Printf("fleet: mTLS listener on :%d stopped", port)
	}
	if s.closePort != nil && port != 0 {
		if err := s.closePort(port); err != nil {
			log.Printf("fleet: could not close firewall port %d: %v", port, err)
		}
	}
}

// stopLocked shuts the current listener (and any lingering migration listener) and
// closes their firewall ports. Caller holds s.mu.
func (s *Service) stopLocked() {
	s.closeListenerLocked(s.srv, s.port)
	s.srv = nil
	if s.oldSrv != nil {
		s.closeListenerLocked(s.oldSrv, s.oldPort)
		s.oldSrv, s.oldPort = nil, 0
	}
	s.migrating = false
	s.migrateIDs = nil
	s.enabled = false
}

// portMigrationGrace bounds how long the OLD port stays open after a change: agents
// online at the time migrate within ~10s (their poll interval); this cap only affects
// machines powered off during the window (they strand and need reinstall).
const portMigrationGrace = 5 * time.Minute

// beginPortMigration switches the listener to newPort WITHOUT stranding agents: it opens
// the new port while keeping the old one live, queues set-panel-port for every enrolled
// machine, and closes the old port once all have acked or after portMigrationGrace.
// Caller must have verified a real port change with machines present and no migration
// already in flight.
func (s *Service) beginPortMigration(oldPort, newPort int, machines []Machine) {
	payload, _ := json.Marshal(map[string]int{"port": newPort})
	ids := make([]string, 0, len(machines))
	for _, m := range machines {
		id, err := s.Enqueue(m.ID, "set-panel-port", payload)
		if err != nil {
			log.Printf("fleet: queue set-panel-port for %s: %v", m.ID, err)
			continue
		}
		ids = append(ids, id)
		s.broadcastCommands(m.ID)
	}

	s.mu.Lock()
	s.oldSrv, s.oldPort = s.srv, s.port
	s.srv = nil
	s.startListenerLocked(newPort) // sets s.srv + s.port to the new listener
	s.migrating = true
	s.migrateEndsAt = time.Now().Add(portMigrationGrace)
	s.migrateIDs = ids
	s.mu.Unlock()

	log.Printf("fleet: port migration %d -> %d, notified %d machine(s); old port open up to %s",
		oldPort, newPort, len(ids), portMigrationGrace)
	go s.watchMigration()
}

// watchMigration closes the old listener once every migrated machine has acked
// set-panel-port, or when the grace window expires — whichever comes first.
func (s *Service) watchMigration() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for range tick.C {
		s.mu.Lock()
		if !s.migrating {
			s.mu.Unlock()
			return
		}
		expired := time.Now().After(s.migrateEndsAt)
		if !expired && !s.allAckedLocked() {
			s.mu.Unlock()
			continue
		}
		s.closeListenerLocked(s.oldSrv, s.oldPort)
		reason := "all agents acked"
		if expired {
			reason = "grace window elapsed"
		}
		log.Printf("fleet: port migration complete (%s) — old port %d closed", reason, s.oldPort)
		s.oldSrv, s.oldPort = nil, 0
		s.migrating = false
		s.migrateIDs = nil
		s.mu.Unlock()
		return
	}
}

// allAckedLocked reports whether every set-panel-port command from the current migration
// has been acked (status left pending/delivered) — i.e. the agent received it. Caller
// holds s.mu.
func (s *Service) allAckedLocked() bool {
	if len(s.migrateIDs) == 0 {
		return true
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(s.migrateIDs)), ",")
	args := make([]any, len(s.migrateIDs))
	for i, id := range s.migrateIDs {
		args[i] = id
	}
	var pending int
	q := `SELECT COUNT(*) FROM fleet_commands WHERE id IN (` + placeholders + `) AND status IN ('pending','delivered')`
	if err := s.db.QueryRow(q, args...).Scan(&pending); err != nil {
		return false
	}
	return pending == 0
}

// migrationState reports whether a live port migration is in progress and when its
// grace window (both ports open) ends.
func (s *Service) migrationState() (active bool, endsAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.migrating, s.migrateEndsAt
}

// enrolledMachines returns the machines a port change must reach: enrolled, not revoked,
// not already uninstalled. The DB error is propagated so a change-time hiccup aborts the
// port change rather than silently downgrading to the stranding hard-switch path.
func (s *Service) enrolledMachines() ([]Machine, error) {
	all, err := s.ListMachines()
	if err != nil {
		return nil, err
	}
	out := make([]Machine, 0, len(all))
	for _, m := range all {
		if m.Revoked || m.Status == "uninstalled" {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// Status reports the current listener state (for the admin UI).
func (s *Service) Status() (enabled bool, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv != nil, s.port
}

// HostCandidates returns the direct addresses an agent could dial for mTLS: the panel's
// public IPv4(s) plus its WireGuard interface IP. Docker/bridge private IPs and the
// (possibly Cloudflare-proxied) SSL domain are deliberately excluded — the mTLS channel
// must reach the origin directly, and only these are meaningful to pick for that. Order:
// public IPs first, then WG. (detectHostSANs still lists everything for the cert SANs.)
func (s *Service) HostCandidates() []string {
	pub, wg := []string{}, []string{}
	seen := map[string]bool{}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		isWG := strings.HasPrefix(iface.Name, "wg")
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil || seen[ipnet.IP.String()] {
				continue
			}
			ip := ipnet.IP.String()
			if isPublicIPv4(ipnet.IP) {
				seen[ip] = true
				pub = append(pub, ip)
			} else if isWG && ipnet.IP.IsPrivate() {
				seen[ip] = true
				wg = append(wg, ip)
			}
		}
	}
	return append(pub, wg...)
}

// firstPublicIP returns the panel's first routable public IPv4, used as the default
// mTLS host when a token didn't record one. The agent's mTLS channel must reach the
// origin DIRECTLY (a Cloudflare-proxied domain only forwards 80/443 and can't pass
// client certs), so this is an IP, not the download domain.
func firstPublicIP() string {
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && isPublicIPv4(ipnet.IP) {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

// isPublicIPv4 reports whether ip is a routable public IPv4 (not loopback/link-local/
// private/CGNAT).
func isPublicIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return false
	}
	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 { // CGNAT 100.64.0.0/10
		return false
	}
	return true
}

// detectHostSANs enumerates this host's non-loopback IPs (WG IP, LAN, public…)
// plus the configured SSL domain. Used both for the server cert SANs and the UI's
// address picker, so the cert is valid for whatever address the agent uses.
func detectHostSANs(sslDomain string) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			add(ipnet.IP.String())
		}
	}
	add(sslDomain)
	return out
}

func (s *Service) getSetting(key string) string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v
}

// setSetting persists a fleet config value into the shared settings table (same
// form the settings service uses).
func (s *Service) setSetting(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO settings (key, value, encrypted, updated_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = ?, encrypted = 0, updated_at = CURRENT_TIMESTAMP`,
		key, value, value)
	return err
}

func parsePort(v string) (int, error) {
	p, err := strconv.Atoi(v)
	if err != nil || p < 1 || p > 65535 {
		return 0, errBadPort
	}
	return p, nil
}

// sweepOrphans deletes child rows whose machine no longer exists in fleet_machines.
// DeleteMachine cascades today, but rows can be orphaned by a delete that predates that
// cascade (the CVE feature shipped ~2h before delete-clears-CVEs landed). Runs once at
// boot as a self-heal. Table names are compile-time constants, so the DELETEs carry no
// user input; NOT EXISTS is NULL-safe (unlike NOT IN over a nullable subquery). Returns
// the total rows removed so the caller can decide whether to VACUUM.
func sweepOrphans(db *sql.DB) int64 {
	var total int64
	for _, tbl := range []string{"fleet_cves", "fleet_metrics", "fleet_commands"} {
		res, err := db.Exec(`DELETE FROM ` + tbl + ` WHERE NOT EXISTS (` +
			`SELECT 1 FROM fleet_machines m WHERE m.id = ` + tbl + `.machine_id)`)
		if err != nil {
			log.Printf("fleet: orphan sweep %s: %v", tbl, err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("fleet: orphan sweep removed %d rows from %s", n, tbl)
			total += n
		}
	}
	return total
}

func ensureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS fleet_ca (
			id         INTEGER PRIMARY KEY,
			cert_pem   TEXT NOT NULL,
			key_enc    TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS fleet_tokens (
			token_hash TEXT PRIMARY KEY,
			label      TEXT,
			panel_host TEXT,
			expires_at TEXT NOT NULL,
			used       INTEGER DEFAULT 0,
			used_at    TEXT,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS fleet_machines (
			id           TEXT PRIMARY KEY,
			name         TEXT,
			machine_hash TEXT,
			cert_fp      TEXT,
			wg_pubkey    TEXT,
			status       TEXT DEFAULT 'enrolled',
			last_report  TEXT,
			enrolled_at  TEXT NOT NULL,
			last_seen    TEXT,
			revoked      INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS fleet_commands (
			id           TEXT PRIMARY KEY,
			machine_id   TEXT NOT NULL,
			type         TEXT NOT NULL,
			payload      TEXT,
			status       TEXT DEFAULT 'pending',
			result       TEXT,
			created_at   TEXT NOT NULL,
			delivered_at TEXT,
			done_at      TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fleet_cmd_machine ON fleet_commands(machine_id, status)`,
		`CREATE TABLE IF NOT EXISTS fleet_cves (
			machine_id TEXT NOT NULL,
			cve_id     TEXT NOT NULL,
			pkg        TEXT,
			installed  TEXT,
			fixed      TEXT,
			severity   TEXT,
			target     TEXT,
			project    TEXT,
			class      TEXT,
			type       TEXT,
			title      TEXT,
			scanned_at TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fleet_cves_machine ON fleet_cves(machine_id, severity)`,
		`CREATE TABLE IF NOT EXISTS fleet_metrics (
			machine_id TEXT NOT NULL,
			bucket     INTEGER NOT NULL,
			cpu_avg  REAL, cpu_max  REAL,
			mem_avg  REAL, mem_max  REAL,
			disk_avg REAL, disk_max REAL,
			load_avg REAL, load_max REAL,
			samples  INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (machine_id, bucket)
		)`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	// Migrations for DBs created before these columns existed (ignore "duplicate column").
	// MUST run before any index that references a migrated column (below).
	for _, alt := range []string{
		`ALTER TABLE fleet_tokens ADD COLUMN panel_host TEXT`,
		`ALTER TABLE fleet_cves ADD COLUMN project TEXT`,
	} {
		if _, err := db.Exec(alt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("fleet: migration %q: %v", alt, err)
		}
	}
	// Indexes on migrated columns — created AFTER the migration so an upgraded DB (whose
	// column was just added) doesn't choke on "no such column".
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_fleet_cves_project ON fleet_cves(machine_id, project)`); err != nil {
		log.Printf("fleet: project index: %v", err)
	}
	return nil
}
