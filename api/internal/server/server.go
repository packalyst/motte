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
	return &Service{
		db:          db,
		authLogPath: envOr("AUTH_LOG", "/var/log/auth.log"),
		dpkgLogPath: envOr("DPKG_LOG", "/var/log/dpkg.log"),
	}
}

func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetSecurity": s.handleGetSecurity,
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
}
type loginsBlock struct {
	Recent       []loginEvent `json:"recent"`
	Failed1h     int          `json:"failed_1h"`
	FailedPrev1h int          `json:"failed_prev_1h"`
	FailedIPs1h  int          `json:"failed_ips_1h"`
}
type sudoEvent struct {
	User    string    `json:"user"`
	Command string    `json:"command"`
	When    time.Time `json:"when"`
}
type sudoBlock struct {
	Recent      []sudoEvent `json:"recent"`
	Failures24h int         `json:"failures_24h"`
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
}
type securityReport struct {
	Status   string        `json:"status"` // calm | elevated | under_attack
	Logins   loginsBlock   `json:"logins"`
	Sudo     sudoBlock     `json:"sudo"`
	Accounts accountsBlock `json:"accounts"`
	Packages []pkgEvent    `json:"packages"`
	Ports    portsBlock    `json:"ports"`
	Host     hostBlock     `json:"host"`
	Certs    []CertInfo    `json:"certs"`
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

	rep.Packages = s.recentPackages(now)
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
	reFailed   = regexp.MustCompile(`Failed\s+password\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(\S+)\s+port`)
	reSudoCmd  = regexp.MustCompile(`sudo(?:\[\d+\])?:\s+(\S+)\s+:.*COMMAND=(.+)$`)
	reSudoFail = regexp.MustCompile(`sudo(?:\[\d+\])?:.*(authentication failure|incorrect password attempt)`)
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
	oneHour, twoHour, dayAgo, cutoff time.Time
}

func newAuthAccum(now time.Time) *authAccum {
	a := &authAccum{
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
	if m := reAccepted.FindStringSubmatch(line); m != nil {
		if !ok || ts.Before(a.cutoff) {
			return
		}
		a.out.logins.Recent = append(a.out.logins.Recent, loginEvent{Method: m[1], User: m[2], IP: m[3], When: ts, Root: m[2] == "root"})
		return
	}
	if m := reSudoCmd.FindStringSubmatch(line); m != nil {
		if !ok || ts.Before(a.cutoff) {
			return
		}
		a.out.sudo.Recent = append(a.out.sudo.Recent, sudoEvent{User: m[1], Command: strings.TrimSpace(m[2]), When: ts})
		return
	}
	if reSudoFail.MatchString(line) {
		if ok && ts.After(a.dayAgo) {
			a.out.sudo.Failures24h++
		}
		return
	}
	if m := reNewUser.FindStringSubmatch(line); m != nil {
		if ok && !ts.Before(a.cutoff) {
			a.out.accounts.NewUsers = append(a.out.accounts.NewUsers, acctEvent{Name: m[1], When: ts})
		}
		return
	}
	if m := reNewGroup.FindStringSubmatch(line); m != nil {
		if ok && !ts.Before(a.cutoff) {
			a.out.accounts.NewGroups = append(a.out.accounts.NewGroups, acctEvent{Name: m[1], When: ts})
		}
		return
	}
}

func (a *authAccum) finish() authScan {
	a.out.logins.FailedIPs1h = len(a.failedIPs)
	a.out.logins.Recent = lastN(a.out.logins.Recent, 12)
	a.out.sudo.Recent = lastN(a.out.sudo.Recent, 12)
	return a.out
}

// scanLogins reads recent auth events, preferring journald (Ubuntu 24.04+ ships no
// /var/log/auth.log by default — sshd logs only to the journal) and falling back to
// the log file when the journal isn't reachable.
func (s *Service) scanLogins(now time.Time) authScan {
	if sc, ok := s.scanJournal(now); ok {
		return sc
	}
	acc := newAuthAccum(now)
	forEachTailLine(s.authLogPath, func(line string) {
		ts, ok := parseSyslogTime(line, now)
		acc.line(line, ts, ok)
	})
	return acc.finish()
}

// scanJournal reads sshd/sudo/useradd/groupadd events from the host journal via
// nsenter into PID 1's namespaces (the container is pid:host + privileged, and
// already uses nsenter elsewhere). Returns ok=false if journald isn't reachable so
// the caller falls back to the log file.
func (s *Service) scanJournal(now time.Time) (authScan, bool) {
	acc := newAuthAccum(now)
	// Sparse events over a long window (logins, sudo, account changes). Exclude the
	// noisy "Failed password" brute-force spam so a heavily-attacked host's rare login
	// lines aren't buried — we ask the journal for exactly the lines that matter.
	sparse, ok1 := journalGrep("30 days ago", `Accepted |COMMAND=|new user:|new group:`)
	// The failed-SSH trend only needs the last couple of hours.
	failed, ok2 := journalGrep("3 hours ago", `Failed password`)
	if !ok1 && !ok2 {
		return authScan{}, false // journal not reachable — fall back to the log file
	}
	for _, line := range sparse {
		ts, ok := parseISOTime(line)
		acc.line(line, ts, ok)
	}
	for _, line := range failed {
		ts, ok := parseISOTime(line)
		acc.line(line, ts, ok)
	}
	return acc.finish(), true
}

// journalGrep runs a filtered journalctl over the host journal (authpriv facility) via
// nsenter. ok=false only when journalctl couldn't run at all (so the caller falls back
// to the log file); a non-zero exit with no matches is treated as "ran, empty".
func journalGrep(since, grep string) ([]string, bool) {
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--",
		"journalctl", "-o", "short-iso", "--no-pager", "--facility=authpriv",
		"--since", since, "--grep", grep)
	out, err := cmd.Output()
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
	return h
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

// parseISOTime parses the leading ISO timestamp of a `journalctl -o short-iso`
// line, e.g. "2026-08-16T18:42:01+0200 host sshd[1]: ...".
func parseISOTime(line string) (time.Time, bool) {
	i := strings.IndexByte(line, ' ')
	if i <= 0 {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05-0700", line[:i])
	if err != nil {
		return time.Time{}, false
	}
	return t, true
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
