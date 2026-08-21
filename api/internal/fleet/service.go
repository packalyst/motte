package fleet

import (
	"database/sql"
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

	clientCertTTL time.Duration

	// Usage-history pruning is throttled to once an hour, piggybacked on report
	// traffic (see metrics.go) — no background goroutine.
	metricsMu       sync.Mutex
	metricsPrunedAt time.Time
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
		s.stopLocked()
	}
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

// stopLocked shuts the listener and closes the firewall port. Caller holds s.mu.
func (s *Service) stopLocked() {
	if s.srv != nil {
		_ = s.srv.Close()
		s.srv = nil
		log.Printf("fleet: mTLS listener on :%d stopped", s.port)
	}
	if s.closePort != nil && s.port != 0 {
		if err := s.closePort(s.port); err != nil {
			log.Printf("fleet: could not close firewall port %d: %v", s.port, err)
		}
	}
	s.enabled = false
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
