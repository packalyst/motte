// Package server surfaces host-security telemetry for the "Server" page: who
// logged into the box, privilege use, new accounts, package installs, listening
// ports, host uptime and TLS-cert health. Everything is read-only and comes from
// data the host already produces (/var/log, /proc, `ss`) — the api container is
// already network_mode:host + pid:host + privileged, so this opens no new access.
//
// v1 reads on demand (bounded tail of the log files) rather than running a
// background tailer; the Server page polls infrequently, and the reads are
// capped so a large log never blows up a request. If we later need long-window
// history, promote the parsers to a logs/sources watcher with a persisted offset.
package server

import (
	"bufio"
	"context"
	"database/sql"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"api/internal/router"
)

// maxTailBytes bounds how much of each log file we read per request.
const maxTailBytes = 2 << 20 // 2 MiB

// CertInfo is the slim cert view the Server page needs; main.go adapts
// traefik.CertificateInfo into this so this package stays dependency-light.
type CertInfo struct {
	Domain   string `json:"domain"`
	DaysLeft int    `json:"daysLeft"`
	Status   string `json:"status"`
}

// Service serves GET /api/server/security.
type Service struct {
	db          *sql.DB
	authLogPath string
	dpkgLogPath string

	// Optional hooks, wired by main.go to avoid import cycles.
	Certs     func() []CertInfo                            // TLS certs (traefik)
	GeoLookup func(ip string) (owner string, country string) // enrich login IPs
}

func New(db *sql.DB) *Service {
	s := &Service{
		db:          db,
		authLogPath: envOr("AUTH_LOG", "/var/log/auth.log"),
		dpkgLogPath: envOr("DPKG_LOG", "/var/log/dpkg.log"),
	}
	s.registerSudoWatcher() // capture sudo failures live and persist their session IP
	return s
}

func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetSecurity":        s.handleGetSecurity,
		"ForgetSudoFailure":  s.handleForgetSudoFailure,
	}
}

// ---------- response shapes ----------

type loginEvent struct {
	User    string    `json:"user"`
	IP      string    `json:"ip"`
	Method  string    `json:"method"`  // publickey | password | ...
	Country string    `json:"country,omitempty"`
	Owner   string    `json:"owner,omitempty"`
	When    time.Time `json:"when"`
	Root    bool      `json:"root"`
	Active  bool      `json:"active,omitempty"` // session still open right now (per `who`)
}
type loginsBlock struct {
	Recent       []loginEvent    `json:"recent"`
	Active       []activeSession `json:"active"` // one row per currently-connected (user, IP)
	Failed1h     int             `json:"failed_1h"`
	FailedPrev1h int             `json:"failed_prev_1h"`
	FailedIPs1h  int             `json:"failed_ips_1h"`
}

// activeSession is one currently-connected (user, IP) group for the Access & escalation
// card: how many live connections (from loginctl) and the most recent matching login for
// its time/geo. Sourced from live sessions, not the login ledger, so it can't surface a
// stale record.
type activeSession struct {
	User    string    `json:"user"`
	IP      string    `json:"ip"`
	Count   int       `json:"count"`
	When    time.Time `json:"when"` // most recent matching login (zero if none in the ledger)
	Country string    `json:"country,omitempty"`
	Owner   string    `json:"owner,omitempty"`
	Root    bool      `json:"root"`
}
type sudoEvent struct {
	User    string    `json:"user"`
	Command string    `json:"command"`
	When    time.Time `json:"when"`
}
type sudoFail struct {
	ID      int64     `json:"id"`
	User    string    `json:"user"`
	TTY     string    `json:"tty,omitempty"`
	IP      string    `json:"ip,omitempty"` // resolved from `who` at failure time
	Command string    `json:"command,omitempty"`
	When    time.Time `json:"when"`
}
type sudoBlock struct {
	Recent      []sudoEvent `json:"recent"`
	Failures24h int         `json:"failures_24h"`
	Failed      []sudoFail  `json:"failed"` // persisted failures with session IP
}
type acctEvent struct {
	Name string    `json:"name"`
	When time.Time `json:"when"`
}
type accountsBlock struct {
	NewUsers  []acctEvent `json:"new_users"`
	NewGroups []acctEvent `json:"new_groups"`
}
type pkgEvent struct {
	Action  string    `json:"action"` // install | upgrade | remove
	Package string    `json:"package"`
	Version string    `json:"version,omitempty"`
	When    time.Time `json:"when"`
}
type portRow struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Public  bool   `json:"public"`
	Process string `json:"process,omitempty"`
}
type portsBlock struct {
	Listening []portRow `json:"listening"`
	Public    int       `json:"public"`
}
type hostBlock struct {
	UptimeSeconds int64     `json:"uptime_seconds"`
	BootTime      time.Time `json:"boot_time"`
	RebootRecent  bool      `json:"reboot_recent"` // booted < 24h ago
	Hostname      string    `json:"hostname,omitempty"`
	Distro        string    `json:"distro,omitempty"`   // /etc/os-release PRETTY_NAME
	Kernel        string    `json:"kernel,omitempty"`   // uname -r
	Timezone      string    `json:"timezone,omitempty"` // IANA name, or zone abbrev
}
type securityReport struct {
	Status      string        `json:"status"` // calm | elevated | under_attack
	Logins      loginsBlock   `json:"logins"`
	Sudo        sudoBlock     `json:"sudo"`
	Accounts    accountsBlock `json:"accounts"`
	Packages    []pkgEvent    `json:"packages"`
	PhoneHome   phoneBlock    `json:"phone_home"`
	Persistence persistBlock  `json:"persistence"`
	Ports       portsBlock    `json:"ports"`
	Host        hostBlock     `json:"host"`
	Certs       []CertInfo    `json:"certs"`
}

func (s *Service) handleGetSecurity(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	rep := securityReport{Status: "calm", Certs: []CertInfo{}}

	// Journald (preferred) or auth.log yields logins, sudo, accounts, failed-ssh.
	al := s.scanLogins(now)
	rep.Logins = al.logins
	rep.Sudo = al.sudo
	rep.Accounts = al.accounts

	// Enrich the (few) successful-login source IPs with owner/country.
	if s.GeoLookup != nil {
		for i := range rep.Logins.Recent {
			ip := rep.Logins.Recent[i].IP
			if ip == "" || isLoopback(ip) {
				continue
			}
			if owner, country := s.GeoLookup(ip); owner != "" || country != "" {
				rep.Logins.Recent[i].Owner = owner
				if rep.Logins.Recent[i].Country == "" {
					rep.Logins.Recent[i].Country = country
				}
			}
		}
	}

	// Live sessions come from loginctl (per-connection truth). Flag which ledger records
	// belong to a still-connected (user, IP) so the alarms can exclude them, and build the
	// one-row-per-(user,IP) active list the card shows — from live sessions, not the ledger,
	// so it never surfaces a stale login.
	live := activeSessions()
	markActiveMembership(rep.Logins.Recent, live.counts)
	rep.Logins.Active = buildActiveSessions(rep.Logins.Recent, live)

	rep.Packages = s.recentPackages(now)
	rep.Sudo.Failed = s.recentSudoFailures(now) // persisted failures with session IP

	rep.PhoneHome = phoneHome()
	if s.GeoLookup != nil {
		for i := range rep.PhoneHome.Destinations {
			if owner, country := s.GeoLookup(rep.PhoneHome.Destinations[i].IP); owner != "" || country != "" {
				rep.PhoneHome.Destinations[i].Owner = owner
				rep.PhoneHome.Destinations[i].Country = country
			}
		}
	}
	rep.Persistence = persistBlock{PackagesInstalled: len(rep.Packages), CronRecent: cronRecentChanges()}
	rep.Ports = listeningPorts()
	rep.Host = hostUptime(now)
	if s.Certs != nil {
		if c := s.Certs(); c != nil {
			rep.Certs = c
		}
	}
	rep.Status = classify(rep, now)

	router.JSON(w, rep)
}

// ---------- auth.log ----------

// Match on the MESSAGE content, not the process name — OpenSSH 9.8+ (Ubuntu 24.04)
// logs logins under "sshd-session", older ones under "sshd", and journald vs syslog
// format the prefix differently. The content phrasing is stable and SSH-specific.
var (
	reAccepted = regexp.MustCompile(`Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	// Brute-force at the door: password guesses, invalid-user probes, max-attempts.
	reFailed   = regexp.MustCompile(`(?:Failed password|Invalid user|maximum authentication attempts exceeded).*?from\s+(\S+)\s+port`)
	reSudoCmd  = regexp.MustCompile(`sudo(?:\[\d+\])?:\s+(\S+)\s+:.*COMMAND=(.+)$`)
	reSudoFail = regexp.MustCompile(`sudo(?:\[\d+\])?:.*(authentication failure|incorrect password attempt)`)
	reSudoUser = regexp.MustCompile(`sudo(?:\[\d+\])?:\s+(\S+)\s+:`) // invoking user before " :"
	reTTY      = regexp.MustCompile(`TTY=(\S+?)\s*;`)                // the session that ran sudo
	reNewUser  = regexp.MustCompile(`new user:\s+name=([A-Za-z0-9_.-]+)`)
	reNewGroup = regexp.MustCompile(`new group:\s+name=([A-Za-z0-9_.-]+)`)
	// Leading syslog timestamp "Aug  5 18:42:01" (day may be space-padded).
	reSyslogTS = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)
)

type authScan struct {
	logins   loginsBlock
	sudo     sudoBlock
	accounts accountsBlock
}

// authAccum matches parsed auth events from either /var/log/auth.log (syslog
// timestamps) or journald (ISO timestamps) into a single result.
type authAccum struct {
	out                                   authScan
	failedIPs                             map[string]struct{}
	now, oneHour, twoHour, dayAgo, cutoff time.Time
}

func newAuthAccum(now time.Time) *authAccum {
	a := &authAccum{
		now:       now,
		oneHour:   now.Add(-time.Hour),
		twoHour:   now.Add(-2 * time.Hour),
		dayAgo:    now.Add(-24 * time.Hour),
		cutoff:    now.Add(-30 * 24 * time.Hour),
		failedIPs: map[string]struct{}{},
	}
	a.out.accounts.NewUsers = []acctEvent{}
	a.out.accounts.NewGroups = []acctEvent{}
	a.out.logins.Recent = []loginEvent{}
	a.out.sudo.Recent = []sudoEvent{}
	return a
}

func (a *authAccum) line(line string, ts time.Time, ok bool) {
	if m := reFailed.FindStringSubmatch(line); m != nil {
		if ok {
			if ts.After(a.oneHour) {
				a.out.logins.Failed1h++
				a.failedIPs[m[1]] = struct{}{}
			} else if ts.After(a.twoHour) {
				a.out.logins.FailedPrev1h++
			}
		}
		return
	}
	// For the list events (logins, sudo, account changes) an unparseable timestamp
	// must NOT drop the event — better to show it with the current time than hide a
	// real login. Only skip when we KNOW it's older than the window.
	if m := reAccepted.FindStringSubmatch(line); m != nil {
		if ok && ts.Before(a.cutoff) {
			return
		}
		a.out.logins.Recent = append(a.out.logins.Recent, loginEvent{Method: m[1], User: m[2], IP: m[3], When: a.when(ts, ok), Root: m[2] == "root"})
		return
	}
	if m := reSudoCmd.FindStringSubmatch(line); m != nil {
		if ok && ts.Before(a.cutoff) {
			return
		}
		a.out.sudo.Recent = append(a.out.sudo.Recent, sudoEvent{User: m[1], Command: strings.TrimSpace(m[2]), When: a.when(ts, ok)})
		return
	}
	if reSudoFail.MatchString(line) {
		if !ok || ts.After(a.dayAgo) {
			a.out.sudo.Failures24h++
		}
		return
	}
	if m := reNewUser.FindStringSubmatch(line); m != nil {
		if !ok || !ts.Before(a.cutoff) {
			a.out.accounts.NewUsers = append(a.out.accounts.NewUsers, acctEvent{Name: m[1], When: a.when(ts, ok)})
		}
		return
	}
	if m := reNewGroup.FindStringSubmatch(line); m != nil {
		if !ok || !ts.Before(a.cutoff) {
			a.out.accounts.NewGroups = append(a.out.accounts.NewGroups, acctEvent{Name: m[1], When: a.when(ts, ok)})
		}
		return
	}
}

// when returns the parsed time, or "now" when the line's timestamp couldn't be parsed.
func (a *authAccum) when(ts time.Time, ok bool) time.Time {
	if ok {
		return ts
	}
	return a.now
}

func (a *authAccum) finish() authScan {
	a.out.logins.FailedIPs1h = len(a.failedIPs)
	a.out.logins.Recent = lastN(a.out.logins.Recent, 12)
	a.out.sudo.Recent = lastN(a.out.sudo.Recent, 12)
	return a.out
}

// scanLogins reads recent auth events. It prefers the systemd journal: unlike
// /var/log/auth.log (which rotates — the current file holds only the slice since the last
// rotation, and we don't read the rotated auth.log.N/.gz files), the journal keeps the
// full window and is distro-neutral. It falls back to the text log file only when the
// journal isn't reachable (older/non-systemd hosts): Debian/Ubuntu = /var/log/auth.log,
// RHEL/Fedora = /var/log/secure. An unparseable timestamp never drops an event.
func (s *Service) scanLogins(now time.Time) authScan {
	// 1) Journal first — used when it's reachable AND actually carried auth events.
	jsc, jok := s.scanJournal(now)
	if jok && authScanHasSignal(jsc) {
		return jsc
	}
	// 2) Text log file fallback (older/non-systemd hosts, or a journal with nothing useful).
	for _, path := range s.authLogCandidates() {
		acc := newAuthAccum(now)
		forEachTailLine(path, func(line string) {
			ts, ok := parseAnyTime(line, now)
			acc.line(line, ts, ok)
		})
		sc := acc.finish()
		if authScanHasSignal(sc) {
			return sc
		}
	}
	// 3) A reachable-but-empty journal still beats an empty scan.
	if jok {
		return jsc
	}
	return newAuthAccum(now).finish()
}

// authScanHasSignal reports whether a scan parsed any real auth activity, so a file
// with lines but no auth events doesn't shadow the journal as the login source.
func authScanHasSignal(sc authScan) bool {
	return len(sc.logins.Recent) > 0 || sc.logins.Failed1h > 0 || sc.logins.FailedPrev1h > 0 ||
		len(sc.sudo.Recent) > 0 || sc.sudo.Failures24h > 0 ||
		len(sc.accounts.NewUsers) > 0 || len(sc.accounts.NewGroups) > 0
}

func (s *Service) authLogCandidates() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range []string{s.authLogPath, "/var/log/auth.log", "/var/log/secure"} {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// scanJournal reads sshd/sudo/useradd/groupadd events from the host journal via
// nsenter into PID 1's namespaces (the container is pid:host + privileged, and
// already uses nsenter elsewhere). Returns ok=false if journald isn't reachable so
// the caller falls back to the log file.
func (s *Service) scanJournal(now time.Time) (authScan, bool) {
	acc := newAuthAccum(now)
	// Filtering by _COMM (indexed) keeps journald from scanning the whole journal — fast.
	// We pass NO --since: with a since, journalctl's --lines returns the FIRST N entries in
	// the window (oldest), which drops recent logins; without it, --lines returns the most
	// recent N, which is what we want (the 30-day cutoff is re-applied per event in code).
	// The queries are SPLIT so a flood of sudo or brute-force failures can't push the rare
	// login lines out of any one --lines window.
	sshComms := []string{"sshd", "sshd-session"}
	logins, ok1 := journalGrep(append(sshComms, "useradd", "groupadd"), "", `Accepted |new user:|new group:`, 200)
	sudo, ok2 := journalGrep([]string{"sudo"}, "", "", 300) // _COMM=sudo alone; the parser keeps COMMAND=/failures
	// Failed-SSH is a bounded time-window count (Failed1h/FailedPrev1h), NOT a newest-N list —
	// so it KEEPS --since. Without it, a sparse-but-large sshd journal would be walked in full
	// and blow the 6s timeout, silently pinning the brute-force counts at 0 (no fallback fires
	// because the login/sudo sub-queries succeed).
	failed, ok3 := journalGrep(sshComms, "3 hours ago", `Failed password`, 3000)
	if !ok1 && !ok2 && !ok3 {
		return authScan{}, false // journal not reachable — fall back to the log file
	}
	for _, batch := range [][]string{logins, sudo, failed} {
		for _, line := range batch {
			ts, ok := parseISOTime(line)
			acc.line(line, ts, ok)
		}
	}
	return acc.finish(), true
}

// journalGrep runs a filtered journalctl over the host journal (authpriv facility) via
// nsenter. ok=false only when journalctl couldn't run at all (so the caller falls back
// to the log file); a non-zero exit with no matches is treated as "ran, empty".
func journalGrep(comms []string, since, grep string, lines int) ([]string, bool) {
	// Speed comes from filtering by _COMM (the logging program) — an INDEXED journal field,
	// so journald seeks straight to just these programs' entries instead of scanning the
	// whole journal. --grep (unindexed message-text match) then runs only over that small
	// slice, and the code-side regexes are the final filter. NOTE: no --facility filter —
	// sshd logins are not reliably under authpriv (it varies by distro/OpenSSH build), which
	// would drop them. Bounded so a huge/stalled journal can't OOM or hang the request:
	// a context timeout kills a wedged journalctl (then we fall back to the log file), and
	// --lines caps output.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	jargs := []string{"journalctl", "-o", "short-iso", "--no-pager", "--lines", strconv.Itoa(lines)}
	for _, c := range comms {
		jargs = append(jargs, "_COMM="+c)
	}
	if grep != "" {
		jargs = append(jargs, "--grep", grep)
	}
	if since != "" {
		jargs = append(jargs, "--since", since)
	}
	args := append([]string{"-t", "1", "-m", "-u", "-i", "-n", "-p", "--"}, jargs...)
	cmd := exec.CommandContext(ctx, "nsenter", args...)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, false // stalled journalctl — fall back to the log file
	}
	if err != nil {
		if _, isExit := err.(*exec.ExitError); !isExit {
			return nil, false // nsenter/journalctl missing or blocked
		}
		// ExitError: journalctl ran (exit 1 = no matches) — use whatever it printed.
	}
	return strings.Split(string(out), "\n"), true
}

// ---------- dpkg.log ----------

// dpkg.log has a real "2006-01-02 15:04:05" timestamp and lines like
// "2026-08-15 10:00:00 status installed nginx:amd64 1.24.0-1".
var reDpkg = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(install|upgrade|remove)\s+(\S+?):\S+\s+(\S+)`)

func (s *Service) recentPackages(now time.Time) []pkgEvent {
	out := []pkgEvent{}
	cutoff := now.Add(-7 * 24 * time.Hour)
	forEachTailLine(s.dpkgLogPath, func(line string) {
		m := reDpkg.FindStringSubmatch(line)
		if m == nil {
			return
		}
		ts, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
		if err != nil || ts.Before(cutoff) {
			return
		}
		out = append(out, pkgEvent{Action: m[2], Package: m[3], Version: m[4], When: ts})
	})
	return lastN(out, 15)
}

// ---------- listening ports (ss) ----------

var reSSProc = regexp.MustCompile(`users:\(\("([^"]+)"`)

func listeningPorts() portsBlock {
	out := portsBlock{Listening: []portRow{}}
	cmd := exec.Command("ss", "-tulnpH")
	data, err := cmd.Output()
	if err != nil {
		return out
	}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := f[0]
		local := f[4] // addr:port (v6 in [..]:port)
		addr, portStr := splitHostPort(local)
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		pub := isPublicBind(addr)
		key := proto + local
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		row := portRow{Proto: proto, Address: addr, Port: port, Public: pub}
		if m := reSSProc.FindStringSubmatch(line); m != nil {
			row.Process = m[1]
		}
		out.Listening = append(out.Listening, row)
		if pub {
			out.Public++
		}
	}
	return out
}

// ---------- host uptime ----------

func hostUptime(now time.Time) hostBlock {
	var h hostBlock
	// pid:host → /proc/uptime is the host's. First field = seconds since boot.
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if secs, perr := strconv.ParseFloat(f[0], 64); perr == nil {
				h.UptimeSeconds = int64(secs)
				h.BootTime = now.Add(-time.Duration(secs) * time.Second)
				h.RebootRecent = secs < 24*3600
			}
		}
	}
	hostMeta(&h)
	return h
}

// hostMeta fills the descriptive host fields (distro, kernel, hostname, timezone) from the
// host via nsenter. Best-effort — a field that can't be read is left blank.
func hostMeta(h *hostBlock) {
	if out, err := runNsenter("uname", "-r"); err == nil {
		h.Kernel = strings.TrimSpace(out)
	}
	if out, err := runNsenter("uname", "-n"); err == nil {
		h.Hostname = strings.TrimSpace(out)
	}
	if out, err := runNsenter("cat", "/etc/os-release"); err == nil {
		h.Distro = osReleasePretty(out)
	}
	if out, err := runNsenter("timedatectl", "show", "--property=Timezone", "--value"); err == nil && strings.TrimSpace(out) != "" {
		h.Timezone = strings.TrimSpace(out)
	} else if out, err := runNsenter("date", "+%Z"); err == nil {
		h.Timezone = strings.TrimSpace(out)
	}
}

// osReleasePretty extracts a human distro name from /etc/os-release content.
func osReleasePretty(s string) string {
	var name, version string
	for _, line := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(line, "PRETTY_NAME="):
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		case strings.HasPrefix(line, "NAME="):
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		case strings.HasPrefix(line, "VERSION="):
			version = strings.Trim(strings.TrimPrefix(line, "VERSION="), `"`)
		}
	}
	return strings.TrimSpace(name + " " + version)
}

// ---------- status ----------

func classify(rep securityReport, now time.Time) string {
	// Escalate on a successful non-loopback root login in the last hour — the
	// clearest "someone may be inside" signal.
	for _, l := range rep.Logins.Recent {
		if l.Root && l.When.After(now.Add(-time.Hour)) && l.IP != "" && !isLoopback(l.IP) {
			return "under_attack"
		}
	}
	b, prev := rep.Logins.Failed1h, rep.Logins.FailedPrev1h
	spike := prev > 0 && b >= prev*3 && b >= 30
	switch {
	case b >= 500 || spike:
		return "under_attack"
	case b >= 100 || rep.Sudo.Failures24h > 0:
		return "elevated"
	default:
		return "calm"
	}
}

// ---------- helpers ----------

func parseSyslogTime(line string, now time.Time) (time.Time, bool) {
	m := reSyslogTS.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", m[1], time.Local)
	if err != nil {
		return time.Time{}, false
	}
	t = t.AddDate(now.Year(), 0, 0)
	// Syslog has no year: if that lands >24h in the future, it's from last year.
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

// parseAnyTime tries the syslog format first, then ISO — auth.log timestamps vary by
// distro/rsyslog config (classic "Aug 16 18:42:01" vs high-precision ISO8601).
func parseAnyTime(line string, now time.Time) (time.Time, bool) {
	if t, ok := parseSyslogTime(line, now); ok {
		return t, true
	}
	return parseISOTime(line)
}

// isoLayouts covers the ISO-8601 timestamp variants seen across distros/loggers:
// rsyslog high-precision ("…​.387291+03:00"), journald short-iso ("…+0200"),
// UTC "Z", and no-offset forms.
var isoLayouts = []string{
	time.RFC3339Nano,                    // 2006-01-02T15:04:05.999999999Z07:00 (frac + ±HH:MM / Z)
	time.RFC3339,                        // 2006-01-02T15:04:05Z07:00
	"2006-01-02T15:04:05.999999999-0700", // frac + ±HHMM (no colon)
	"2006-01-02T15:04:05-0700",          // journald short-iso, ±HHMM
	"2006-01-02T15:04:05.999999999",     // frac, no offset
	"2006-01-02T15:04:05",               // bare
}

// parseISOTime parses a leading ISO-8601 timestamp token of any common shape.
func parseISOTime(line string) (time.Time, bool) {
	i := strings.IndexByte(line, ' ')
	if i <= 0 {
		return time.Time{}, false
	}
	tok := line[:i]
	for _, layout := range isoLayouts {
		if t, err := time.Parse(layout, tok); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// forEachTailLine reads at most the last maxTailBytes of path and calls fn for
// each complete line (dropping the first partial line if we seeked in).
func forEachTailLine(path string, fn func(string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var start int64
	if fi, err := f.Stat(); err == nil && fi.Size() > maxTailBytes {
		start = fi.Size() - maxTailBytes
		f.Seek(start, 0)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 512*1024) // long sudo COMMAND= lines
	first := true
	for sc.Scan() {
		if first && start > 0 {
			first = false // partial line
			continue
		}
		first = false
		fn(sc.Text())
	}
}

func splitHostPort(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func isPublicBind(addr string) bool {
	switch addr {
	case "0.0.0.0", "::", "*", "[::]", "":
		return true
	}
	return !isLoopback(addr)
}

func isLoopback(ip string) bool {
	ip = strings.Trim(ip, "[]")
	if p := net.ParseIP(ip); p != nil {
		return p.IsLoopback()
	}
	return ip == "127.0.0.1" || ip == "::1"
}

func lastN[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
