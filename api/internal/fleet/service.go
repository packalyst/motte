package fleet

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
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
	sslDomain string          // panel's public domain, if any (added to cert SANs + host options)
	srvCert   serverCertCache // the listener's own certificate (servercert.go)

	// firewall port open/close callbacks (wired to the firewall service in main).
	openPort  func(port int) error
	closePort func(port int) error

	// blockedIPs returns the panel's explicit ip/range blocklist, so the operator can
	// push it onto a machine (sync-blocks). Nil ⇒ push is unavailable.
	blockedIPs func() ([]string, error)

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

	// broadcastFiltered is the scope-aware variant (set to ws.BroadcastFiltered in main): it
	// delivers a fleet event only to subscribers whose principal scope allows the machine, so a
	// scoped operator never receives data for machines outside its scope.
	broadcastFiltered func(channel string, payload any, allow func(userID int64, role, scopeKind, scopeValues string) bool)

	mu      sync.Mutex
	enabled bool
	port    int
	srv     *http.Server

	// cfgMu serializes handleSetConfig so the migrating-check and the migration start are
	// one atomic step — two concurrent config POSTs must not both pass the check.
	cfgMu sync.Mutex

	// Live port migration (dual-listen). When the port changes with agents enrolled, the new
	// listener starts while the old one (oldSrv/oldPort) stays up until every migrating
	// machine has really connected on the new port (migrateMoved), so none are stranded.
	// Normally that takes seconds; machines that haven't moved by migrateEndsAt (offline, or
	// unable to reach the new port) keep the old port open up to portMigrationMax.
	oldSrv          *http.Server
	oldPort         int
	migrating       bool
	migrateStarted  time.Time
	migrateEndsAt   time.Time
	migrateMachines []string             // machines told to move
	migrateMoved    map[string]bool      // machine id -> seen on the new port
	migrateSent     map[string]time.Time // machine id -> when set-panel-port was last queued for it
	migrateExtended bool                 // the grace window passed with machines still to move
	migrateGen      int                  // bumped per migration; an older migration's watcher stops
}

// SetBroadcast wires the WS broadcast fn so report ingests push live to the UI.
func (s *Service) SetBroadcast(fn func(channel string, payload any)) { s.broadcast = fn }

// SetBroadcastFiltered wires the scope-aware WS broadcast fn (ws.BroadcastFiltered).
func (s *Service) SetBroadcastFiltered(fn func(channel string, payload any, allow func(userID int64, role, scopeKind, scopeValues string) bool)) {
	s.broadcastFiltered = fn
}

// scopedBroadcast pushes a fleet event for one machine only to subscribers whose scope allows it.
// Falls back to the unfiltered broadcast only if the filtered fn isn't wired (shouldn't happen).
func (s *Service) scopedBroadcast(machineID, channel string, payload any) {
	if s.broadcastFiltered == nil {
		if s.broadcast != nil {
			s.broadcast(channel, payload)
		}
		return
	}
	m, err := s.machineByID(machineID)
	if err != nil || m == nil {
		return // unknown machine → tell no one (fail closed)
	}
	mm := *m
	s.broadcastFiltered(channel, payload, func(userID int64, role, scopeKind, scopeValues string) bool {
		return scopeAllows(&router.Principal{UserID: userID, Role: role, ScopeKind: scopeKind, ScopeValues: scopeValues}, mm)
	})
}

// New initializes the schema + CA. The listener is NOT started here — call
// ReloadFromSettings() once the firewall callbacks are wired. openPort/closePort
// may be nil (then the firewall isn't touched).
func New(db *sql.DB, sslDomain string, openPort, closePort func(int) error, blockedIPs func() ([]string, error), fwBlockEnabled func() bool) (*Service, error) {
	if err := ensureSchema(db); err != nil {
		return nil, err
	}
	// Self-heal any child rows left behind by a machine that no longer exists (see
	// sweepOrphans). Reclaim the freed file space once if the cleanup was large.
	// A folder-picker request outlives its waiting handler only if the panel stopped mid-wait.
	if _, err := db.Exec(`DELETE FROM fleet_commands WHERE type = 'list-dirs'`); err != nil {
		log.Printf("fleet: clearing folder-picker requests: %v", err)
	}
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
	svc := &Service{
		db:             db,
		ca:             ca,
		sslDomain:      sslDomain,
		openPort:       openPort,
		closePort:      closePort,
		blockedIPs:     blockedIPs,
		fwBlockEnabled: fwBlockEnabled,
		agentCache:     newAgentCache(),
	}
	recordDB = db             // wrapped keys of the encrypted console recordings
	consoleEventService = svc // lets the session-change hooks push live updates to console-events subscribers
	startRecordJanitor()      // console recordings: delete past console_record_days (now + every 6h)
	return svc, nil
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
	// Serialize on cfgMu so a settings reload (startup, or a backup/config restore via
	// Reconcile) can't race handleSetConfig and do the stranding hard-switch the migration
	// path avoids. handleSetConfig already holds cfgMu, so it calls the *Locked variant.
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.reloadFromSettingsLocked()
}

// reloadFromSettingsLocked (re)applies fleet config from the settings table. Caller holds
// s.cfgMu.
func (s *Service) reloadFromSettingsLocked() {
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
		if s.srv != nil || s.migrating { // a migration's old port closes too, even if the new one never started
			s.stopLocked()
		}
		return
	}
	// enabled: (re)start if not running or the port changed.
	if s.srv != nil && s.port == port {
		return
	}
	if s.migrating { // a direct port switch (e.g. a restored backup) replaces a port change in flight
		s.endMigrationLocked()
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
	if s.migrating {
		s.endMigrationLocked()
	}
	s.enabled = false
}

// portMigrationGrace is how long a port change normally keeps the OLD port open: online
// agents reconnect on the new port within seconds. Machines that haven't moved by then
// (powered off, or unable to reach the new port: the agent then goes back to the old address
// after 2 minutes) keep the old port open up to portMigrationMax, then strand.
const (
	portMigrationGrace = 5 * time.Minute
	portMigrationMax   = 24 * time.Hour
	// portMigrationResend: a machine still turning up on the old port is told the new one
	// again this often (it may have fallen back after the new port failed for it, or the
	// panel restarted mid-move), so it keeps trying instead of waiting out the migration.
	portMigrationResend = 10 * time.Minute
)

// beginPortMigration switches the listener to newPort WITHOUT stranding agents: it opens
// the new port while keeping the old one live, queues set-panel-port for every enrolled
// machine, and closes the old port once every one of them has connected on the new port.
// Caller must have verified a real port change with machines present and no migration
// already in flight.
func (s *Service) beginPortMigration(oldPort, newPort int, machines []Machine) {
	payload, _ := json.Marshal(map[string]int{"port": newPort})
	// Any set-panel-port still queued is from an earlier change (one a panel restart cut short) and
	// names a port that is going away.
	s.cancelPending("", "set-panel-port")
	ids := make([]string, 0, len(machines))
	for _, m := range machines {
		if _, err := s.Enqueue(m.ID, "set-panel-port", payload); err != nil {
			log.Printf("fleet: queue set-panel-port for %s: %v", m.ID, err)
			continue
		}
		ids = append(ids, m.ID)
		s.broadcastCommands(m.ID)
	}

	s.mu.Lock()
	s.oldSrv, s.oldPort = s.srv, s.port
	s.srv = nil
	s.startListenerLocked(newPort) // sets s.srv + s.port to the new listener
	gen := s.initMigrationLocked(ids, time.Now())
	s.mu.Unlock()

	log.Printf("fleet: port migration %d -> %d, notified %d machine(s); old port open until they reconnect",
		oldPort, newPort, len(ids))
	go s.watchMigration(gen)
}

// initMigrationLocked records a migration's start: the machines told to move (told at now) and
// its grace window. Returns the migration's generation, which its watcher holds. Caller holds s.mu.
func (s *Service) initMigrationLocked(ids []string, now time.Time) int {
	s.migrating = true
	s.migrateStarted = now
	s.migrateEndsAt = now.Add(portMigrationGrace)
	s.migrateMachines, s.migrateMoved, s.migrateExtended = ids, map[string]bool{}, false
	s.migrateSent = map[string]time.Time{}
	for _, id := range ids {
		s.migrateSent[id] = now
	}
	s.migrateGen++
	return s.migrateGen
}

// noteListenerPort follows a migration from the agents' requests (called for every
// authenticated one): a machine reaching the panel on the new port has moved; one still on the
// old port is sent the new port again, at most every portMigrationResend.
func (s *Service) noteListenerPort(machineID string, r *http.Request) {
	addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	s.mu.Lock()
	resend, newPort := false, s.port
	if s.migrating {
		switch {
		case port == strconv.Itoa(s.port):
			s.migrateMoved[machineID] = true
		case !s.migrateMoved[machineID] && slices.Contains(s.migrateMachines, machineID) &&
			time.Since(s.migrateSent[machineID]) >= portMigrationResend:
			s.migrateSent[machineID] = time.Now()
			resend = true
		}
	}
	s.mu.Unlock()
	if !resend {
		return
	}
	payload, _ := json.Marshal(map[string]int{"port": newPort})
	s.cancelPending(machineID, "set-panel-port") // the new one replaces any it hasn't picked up yet
	id, err := s.Enqueue(machineID, "set-panel-port", payload)
	if err != nil {
		log.Printf("fleet: re-send set-panel-port to %s: %v", machineID, err)
		return
	}
	// The migration may have ended while this was queued (cancelled, finished early, or switched
	// off): its pending commands were cancelled then, but not this one. Take it back.
	s.mu.Lock()
	ended := !s.migrating || s.port != newPort
	s.mu.Unlock()
	if ended {
		s.cancelCommand(id)
		return
	}
	log.Printf("fleet: machine %s is still on the old port; sent it the new port %d again", machineID, newPort)
	s.broadcastCommands(machineID)
}

// watchMigration closes the old listener once every migrating machine has connected on the
// new port. When the grace window passes with machines still to move, it says which ones
// and keeps the old port open for them up to portMigrationMax.
func (s *Service) watchMigration(gen int) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for range tick.C {
		s.mu.Lock()
		stale := s.migrateGen != gen // a newer migration has its own watcher
		s.mu.Unlock()
		if stale || s.migrationStep(time.Now()) {
			return
		}
	}
}

// migrationStep runs one check of a port migration; true once it is over.
func (s *Service) migrationStep(now time.Time) bool {
	pending := s.unmovedMachines()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.migrating {
		return true
	}
	waiting := s.stillUnmovedLocked(pending)
	switch {
	case len(waiting) == 0:
		log.Printf("fleet: port migration complete (every machine reconnected on :%d) — old port %d closed", s.port, s.oldPort)
	case now.Before(s.migrateEndsAt):
		return false
	case !s.migrateExtended:
		s.migrateExtended = true
		s.migrateEndsAt = s.migrateStarted.Add(portMigrationMax)
		msg := fmt.Sprintf("Port change: %d machine(s) haven't reconnected on the new port %d yet (%s); the old port %d stays open for them until %s",
			len(waiting), s.port, strings.Join(waiting, ", "), s.oldPort, s.migrateEndsAt.Format(time.RFC3339))
		log.Printf("fleet: %s", msg)
		events.Audit("fleet", "port_migration_waiting", events.SeverityWarning, "system", "", msg)
		return false
	default:
		s.auditStrandedLocked("system", "", waiting, "the wait for them ran out")
	}
	s.endMigrationLocked()
	return true
}

// finishMigration closes a port change's old port now (an admin's choice), without waiting for
// the machines that haven't moved; they're named in the audit log.
func (s *Service) finishMigration(actor, ip string) {
	pending := s.unmovedMachines()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.migrating {
		return
	}
	waiting := s.stillUnmovedLocked(pending)
	if len(waiting) > 0 {
		s.auditStrandedLocked(actor, ip, waiting, "an admin closed the old port early")
	} else {
		events.Audit("fleet", "port_migration_finished", events.SeverityInfo, actor, ip,
			fmt.Sprintf("Port change: old port %d closed by an admin; every machine had reconnected on port %d", s.oldPort, s.port))
	}
	s.endMigrationLocked()
}

// auditStrandedLocked records the machines a closing old port leaves behind. Caller holds s.mu.
func (s *Service) auditStrandedLocked(actor, ip string, waiting []string, why string) {
	msg := fmt.Sprintf("Port change: old port %d closed (%s); %d machine(s) never reconnected on port %d (%s) and need reinstalling",
		s.oldPort, why, len(waiting), s.port, strings.Join(waiting, ", "))
	log.Printf("fleet: %s", msg)
	events.Audit("fleet", "port_migration_stranded", events.SeverityWarning, actor, ip, msg)
}

// endMigrationLocked closes the old listener and clears the migration. A machine that hasn't
// picked up its set-panel-port yet must not get it later (it would move to a port that may no
// longer be open), so those are cancelled — all in one statement, as agents wait on s.mu. Caller
// holds s.mu.
func (s *Service) endMigrationLocked() {
	s.closeListenerLocked(s.oldSrv, s.oldPort)
	s.oldSrv, s.oldPort = nil, 0
	s.migrating = false
	s.cancelPending("", "set-panel-port")
	s.migrateMachines, s.migrateMoved, s.migrateSent = nil, nil, nil
}

// unmovedMachine is a migrating machine that hasn't connected on the new port yet.
type unmovedMachine struct{ id, name string }

// unmovedMachines lists the migrating machines that still exist (not deleted or revoked) and
// haven't connected on the new port yet. One whose record can't be read counts as still to move
// (a failed read must never let the old port close on it).
func (s *Service) unmovedMachines() []unmovedMachine {
	s.mu.Lock()
	var ids []string
	for _, id := range s.migrateMachines {
		if !s.migrateMoved[id] {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	var out []unmovedMachine
	for _, id := range ids {
		var name string
		err := s.db.QueryRow(`SELECT name FROM fleet_machines WHERE id = ? AND revoked = 0`, id).Scan(&name)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			continue // deleted or revoked: nothing left to wait for
		case err != nil:
			name = id
		}
		out = append(out, unmovedMachine{id, name})
	}
	return out
}

// stillUnmovedLocked drops the machines that moved since unmovedMachines read them (it reads the
// database outside s.mu) and returns the rest by name. Caller holds s.mu.
func (s *Service) stillUnmovedLocked(pending []unmovedMachine) []string {
	var names []string
	for _, m := range pending {
		if !s.migrateMoved[m.id] {
			names = append(names, m.name)
		}
	}
	return names
}

// migrationState reports whether a live port migration is in progress and when the old port
// is due to close at the latest.
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

// isPublicIPv4 reports whether ip is a routable public IPv4 (see helper.IsNonPublicIP).
func isPublicIPv4(ip net.IP) bool {
	return ip.To4() != nil && !helper.IsNonPublicIP(ip)
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

// setSettingsTx writes several settings in one transaction, so a mid-write failure can't
// leave a half-applied pair (e.g. the new enabled flag with the old port).
func (s *Service) setSettingsTx(kv map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for k, v := range kv {
		if _, err := tx.Exec(`
			INSERT INTO settings (key, value, encrypted, updated_at)
			VALUES (?, ?, 0, CURRENT_TIMESTAMP)
			ON CONFLICT(key) DO UPDATE SET value = ?, encrypted = 0, updated_at = CURRENT_TIMESTAMP`,
			k, v, v); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
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
	for _, tbl := range machineDataTables {
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
			created_at TEXT NOT NULL,
			machine_id TEXT -- set for a re-enroll token: the machine it re-issues a certificate for
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
			revoked      INTEGER DEFAULT 0,
			tags         TEXT DEFAULT '',
			console_enabled INTEGER DEFAULT 0,
			console_record  INTEGER DEFAULT 0
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
			done_at      TEXT,
			expires_at   TEXT
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
		// One summary row per vulnerability scan (scans.go); the findings live in fleet_cves.
		`CREATE TABLE IF NOT EXISTS fleet_scans (
			machine_id  TEXT NOT NULL,
			scanned_at  TEXT NOT NULL,
			trigger     TEXT NOT NULL,
			status      TEXT NOT NULL,
			error       TEXT,
			seconds     REAL,
			peak_mem    INTEGER,
			findings    INTEGER,
			cves        INTEGER,
			critical    INTEGER,
			high        INTEGER,
			medium      INTEGER,
			low         INTEGER,
			unknown     INTEGER,
			fixable     INTEGER,
			new_count   INTEGER,
			fixed_count INTEGER,
			new_ids     TEXT,
			fixed_ids   TEXT,
			PRIMARY KEY (machine_id, scanned_at)
		)`,
		`CREATE TABLE IF NOT EXISTS fleet_fim (
			machine_id TEXT NOT NULL,
			action     TEXT,
			path       TEXT,
			sha256     TEXT,
			event_time TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fleet_fim_machine ON fleet_fim(machine_id)`,
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
		// Per-recording data keys (console recordings are encrypted at rest; see console_record_crypt.go).
		`CREATE TABLE IF NOT EXISTS fleet_console_rec_keys (
			name       TEXT PRIMARY KEY,
			key_enc    TEXT NOT NULL,
			created_at INTEGER NOT NULL
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
		`ALTER TABLE fleet_tokens ADD COLUMN machine_id TEXT`, // re-enroll tokens
		`ALTER TABLE fleet_cves ADD COLUMN project TEXT`,
		`ALTER TABLE fleet_machines ADD COLUMN tags TEXT DEFAULT ''`,              // RBAC tag-scoping
		`ALTER TABLE fleet_machines ADD COLUMN console_enabled INTEGER DEFAULT 0`, // browser console gate (point 7)
		`ALTER TABLE fleet_machines ADD COLUMN console_record INTEGER DEFAULT 0`,  // per-host session recording
		`ALTER TABLE fleet_machines ADD COLUMN last_ip TEXT DEFAULT ''`,           // source address of the last report
		`ALTER TABLE fleet_commands ADD COLUMN expires_at TEXT`,                   // a person's command expires if undelivered
		`ALTER TABLE fleet_machines ADD COLUMN cert_expires TEXT`,                 // current client cert's expiry
		`ALTER TABLE fleet_machines ADD COLUMN cert_fp_next TEXT`,                 // renewed cert, until first used (renew.go)
		`ALTER TABLE fleet_machines ADD COLUMN cert_expires_next TEXT`,
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
