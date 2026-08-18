package fleet

import (
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
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
	db         *sql.DB
	ca         *CA
	installURL string // where install.sh is fetched from (GitHub latest, by default)
	sslDomain  string // panel's public domain, if any (added to cert SANs + host options)

	// firewall port open/close callbacks (wired to the firewall service in main).
	openPort  func(port int) error
	closePort func(port int) error

	mu      sync.Mutex
	enabled bool
	port    int
	srv     *http.Server

	clientCertTTL time.Duration
}

// New initializes the schema + CA. The listener is NOT started here — call
// ReloadFromSettings() once the firewall callbacks are wired. openPort/closePort
// may be nil (then the firewall isn't touched).
func New(db *sql.DB, installURL, sslDomain string, openPort, closePort func(int) error) (*Service, error) {
	if err := ensureSchema(db); err != nil {
		return nil, err
	}
	ca, err := loadOrCreateCA(db)
	if err != nil {
		return nil, err
	}
	if installURL == "" {
		installURL = "https://github.com/packalyst/wireguard-admin-panel/releases/latest/download/install.sh"
	}
	return &Service{
		db:            db,
		ca:            ca,
		installURL:    installURL,
		sslDomain:     sslDomain,
		openPort:      openPort,
		closePort:     closePort,
		clientCertTTL: 90 * 24 * time.Hour,
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

// HostCandidates returns the addresses agents could dial the panel on — every
// non-loopback interface IP plus the SSL domain — so the admin UI can offer them
// when building an install command.
func (s *Service) HostCandidates() []string {
	return detectHostSANs(s.sslDomain)
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
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}
