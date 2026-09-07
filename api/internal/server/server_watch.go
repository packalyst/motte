package server

import (
	"context"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"api/internal/router"
	"api/internal/routines"
)

// ---------- live sudo-failure capture ----------
//
// A failed sudo has no source IP in the line, only a TTY (pts/2). But while the
// offending session is still open — and a fresh failure means someone is right
// there — `who` maps that TTY to the login IP. So a background watcher tails the
// auth log, resolves TTY -> IP at failure time, and PERSISTS it, so the attempt
// (and its IP) survive the session logging out. This is the "intruder escalating"
// signal; we record and surface it, and the admin decides whether to ban.

var reCommand = regexp.MustCompile(`COMMAND=(.+)$`)

func (s *Service) ensureSudoTable() {
	s.db.Exec(`CREATE TABLE IF NOT EXISTS sudo_failures (
		ts          TEXT,
		user        TEXT,
		tty         TEXT,
		ip          TEXT,
		command     TEXT,
		dismissed   INTEGER DEFAULT 0,
		inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(ts, tty)
	)`)
	// Add the column on installs that created the table before it existed (no-op otherwise).
	s.db.Exec(`ALTER TABLE sudo_failures ADD COLUMN dismissed INTEGER DEFAULT 0`)
}

// runSudoWatcher polls the auth log for sudo failures, resolving each to its
// session IP while the session is still active, and persists it. Runs for the
// process lifetime.
func (s *Service) registerSudoWatcher() {
	s.ensureSudoTable()
	routines.Register(routines.Spec{
		Name:        "sudo-watcher",
		Description: "Scan the host auth log for sudo failures and persist their session IP",
		Interval:    15 * time.Second,
		RunAtStart:  true,
		Run:         func(context.Context) error { s.scanSudoFailures(); return nil },
	})
}

func (s *Service) scanSudoFailures() {
	who := whoSessions() // tty -> ip, resolved fresh each pass
	for _, path := range s.authLogCandidates() {
		any := false
		forEachTailLine(path, func(line string) {
			any = true
			if !reSudoFail.MatchString(line) {
				return
			}
			ts, ok := parseAnyTime(line, time.Now())
			tsStr := ""
			if ok {
				tsStr = ts.Format(time.RFC3339)
			}
			s.db.Exec(`INSERT OR IGNORE INTO sudo_failures (ts,user,tty,ip,command) VALUES (?,?,?,?,?)`,
				tsStr, group1(reSudoUser, line), group1(reTTY, line), who[group1(reTTY, line)], group1(reCommand, line))
		})
		if any {
			break // first log source with content wins
		}
	}
	s.db.Exec(`DELETE FROM sudo_failures WHERE inserted_at < datetime('now','-30 days')`)
}

func (s *Service) recentSudoFailures(now time.Time) []sudoFail {
	s.ensureSudoTable()
	out := []sudoFail{}
	rows, err := s.db.Query(`SELECT rowid, ts, user, tty, ip, command FROM sudo_failures
		WHERE COALESCE(dismissed, 0) = 0
		ORDER BY inserted_at DESC LIMIT 15`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var f sudoFail
		var ts string
		if rows.Scan(&f.ID, &ts, &f.User, &f.TTY, &f.IP, &f.Command) != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			f.When = t
		} else {
			f.When = now
		}
		out = append(out, f)
	}
	return out
}

// handleForgetSudoFailure deletes one recorded sudo failure — "I recognize this
// one, dismiss it." DELETE /api/server/sudo-failure/{id}.
func (s *Service) handleForgetSudoFailure(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/server/sudo-failure/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}
	// Mark dismissed rather than delete: the failure line is still in the auth log, so a
	// deleted row would be re-inserted on the next watcher pass. Keeping the (dismissed)
	// row makes the watcher's INSERT OR IGNORE keep skipping it.
	s.db.Exec(`UPDATE sudo_failures SET dismissed = 1 WHERE rowid = ?`, id)
	router.JSON(w, map[string]bool{"ok": true})
}

// runWho returns the raw `who` output lines from the host (via nsenter, since the
// api container must see the host's sessions, not its own). Empty on failure.
func runWho() []string {
	out, err := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "who").Output()
	if err != nil {
		if out, err = exec.Command("who").Output(); err != nil {
			return nil
		}
	}
	return strings.Split(string(out), "\n")
}

// whoHost extracts the remote host/IP from a `who` line's trailing "(...)", or ""
// for a local console session (no parenthetical, or an X display like ":0").
func whoHost(line string) string {
	i := strings.LastIndex(line, "(")
	if i < 0 {
		return ""
	}
	host := strings.Trim(strings.TrimSpace(line[i:]), "()")
	if host == "" || strings.HasPrefix(host, ":") {
		return ""
	}
	return host
}

// whoSessions maps an active session TTY (pts/2, tty1) to its source IP via `who`
// on the host. Local console sessions have no remote IP (skipped).
func whoSessions() map[string]string {
	m := map[string]string{}
	for _, line := range runWho() {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if host := whoHost(line); host != "" {
			m[f[1]] = host
		}
	}
	return m
}

// liveSessions is the set of currently-open sessions: a per-(user\x00IP) connection count,
// plus the most recent session start time per key. The times come from loginctl's own
// session Timestamp (authoritative — no dependence on the login ledger); newest is empty for
// the `who` fallback.
type liveSessions struct {
	counts map[string]int
	newest map[string]time.Time
}

// activeSessions returns the currently-open sessions from systemd-logind (loginctl) — the
// authoritative per-connection view, with each session's real start time. Falls back to
// `who` (counts only, no times) on non-systemd hosts or when loginctl isn't reachable.
func activeSessions() liveSessions {
	if ls, ok := loginctlSessions(); ok {
		return ls
	}
	// Fallback: `who` (one row per pty — may over-count multiplexed connections; no time).
	counts := map[string]int{}
	for _, line := range runWho() {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if host := whoHost(line); host != "" {
			counts[f[0]+"\x00"+host]++
		}
	}
	return liveSessions{counts: counts, newest: map[string]time.Time{}}
}

// sessionIDRe bounds a loginctl session id to a safe token before it's ever passed to
// `loginctl show-session` — defense in depth even though the ids come from loginctl itself.
var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$`)

// runNsenter runs a command inside the host namespaces (via nsenter, argv — never a shell)
// and returns stdout. Mirrors runWho's host-visibility approach.
func runNsenter(args ...string) (string, error) {
	base := []string{"-t", "1", "-m", "-u", "-i", "-n", "-p", "--"}
	out, err := exec.Command("nsenter", append(base, args...)...).Output()
	return string(out), err
}

// hostTZOffset returns the host's current UTC offset as a fixed zone. loginctl prints session
// times in local wall-clock with only a zone abbreviation ("EEST") that Go can't parse, so we
// read the numeric offset from the host via `date +%z` and apply it. UTC if unreadable.
func hostTZOffset() *time.Location {
	out, err := runNsenter("date", "+%z")
	s := strings.TrimSpace(out)
	if err != nil || len(s) != 5 || (s[0] != '+' && s[0] != '-') {
		return time.UTC
	}
	hh, e1 := strconv.Atoi(s[1:3])
	mm, e2 := strconv.Atoi(s[3:5])
	if e1 != nil || e2 != nil {
		return time.UTC
	}
	secs := hh*3600 + mm*60
	if s[0] == '-' {
		secs = -secs
	}
	return time.FixedZone("host", secs)
}

// parseLoginctlTime parses loginctl's "Sun 2026-09-06 15:10:50 EEST": drop the leading weekday
// and trailing zone abbreviation, interpret the wall clock in the host's offset.
func parseLoginctlTime(s string, loc *time.Location) time.Time {
	f := strings.Fields(s) // [Sun, 2026-09-06, 15:10:50, EEST]
	if len(f) < 3 {
		return time.Time{}
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", f[1]+" "+f[2], loc)
	if err != nil {
		return time.Time{}
	}
	return t
}

// loginctlSessions returns currently-open sessions keyed by user+remote-IP via systemd-logind,
// with each key's most recent session start time (loginctl's own Timestamp). Returns ok=false
// when loginctl can't be reached (caller falls back to `who`); ok=true with empty maps means
// "reachable, no remote sessions". Only sessions with a parseable remote IP are counted (local
// console sessions have none), and each RemoteHost is validated as an IP so a crafted value
// can't be matched against IP-based login records.
func loginctlSessions() (liveSessions, bool) {
	listOut, err := runNsenter("loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return liveSessions{}, false // loginctl not reachable — signal fallback to who
	}
	var ids []string
	for _, line := range strings.Split(listOut, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && sessionIDRe.MatchString(f[0]) {
			ids = append(ids, f[0])
		}
	}
	ls := liveSessions{counts: map[string]int{}, newest: map[string]time.Time{}}
	if len(ids) == 0 {
		return ls, true // reachable, no sessions
	}

	// One show-session call for all ids; properties print per session, blocks separated by a
	// blank line.
	args := append([]string{"loginctl", "show-session", "--property=Name", "--property=RemoteHost", "--property=Timestamp"}, ids...)
	showOut, err := runNsenter(args...)
	if err != nil {
		return liveSessions{}, false
	}
	loc := hostTZOffset()
	var user, host string
	var when time.Time
	flush := func() {
		if user != "" && host != "" && net.ParseIP(host) != nil {
			key := user + "\x00" + host
			ls.counts[key]++
			if when.After(ls.newest[key]) {
				ls.newest[key] = when
			}
		}
		user, host, when = "", "", time.Time{}
	}
	for _, line := range strings.Split(showOut, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			flush() // block separator
		case strings.HasPrefix(line, "Name="):
			user = strings.TrimPrefix(line, "Name=")
		case strings.HasPrefix(line, "RemoteHost="):
			host = strings.TrimPrefix(line, "RemoteHost=")
		case strings.HasPrefix(line, "Timestamp="):
			when = parseLoginctlTime(strings.TrimPrefix(line, "Timestamp="), loc)
		}
	}
	flush() // final block has no trailing blank line
	return ls, true
}

// markActiveMembership flags each ledger record whose (user, IP) currently has at least one
// live session, so the "closed session" alarms can exclude the ones that are still connected.
// It does NOT drive the active-session display — that comes from buildActiveSessions, which
// is sourced from live sessions rather than the ledger (so it can't surface a stale login).
func markActiveMembership(recent []loginEvent, counts map[string]int) {
	for i := range recent {
		if recent[i].IP == "" {
			continue
		}
		if counts[recent[i].User+"\x00"+recent[i].IP] > 0 {
			recent[i].Active = true
		}
	}
}

// buildActiveSessions turns the live sessions into one row per (user, IP): the live connection
// count and the newest session start time — taken from loginctl's own Timestamp (authoritative,
// so it can't surface a stale login). The login ledger only supplies country/owner (loginctl has
// none) and a fallback time when loginctl gave none (the `who` path).
func buildActiveSessions(recent []loginEvent, live liveSessions) []activeSession {
	out := []activeSession{}
	for key, n := range live.counts {
		if n <= 0 {
			continue
		}
		user, ip, ok := strings.Cut(key, "\x00")
		if !ok || ip == "" {
			continue
		}
		s := activeSession{User: user, IP: ip, Count: n, Root: user == "root", When: live.newest[key]}
		// loginctl has no geo — pull country/owner (and a fallback time) from the newest
		// matching ledger record.
		var ledgerWhen time.Time
		for _, l := range recent {
			if l.User == user && l.IP == ip && l.When.After(ledgerWhen) {
				ledgerWhen = l.When
				s.Country, s.Owner = l.Country, l.Owner
			}
		}
		if s.When.IsZero() {
			s.When = ledgerWhen
		}
		out = append(out, s)
	}
	// Most recent first, then by user for stability.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].When.Equal(out[j].When) {
			return out[i].When.After(out[j].When)
		}
		return out[i].User < out[j].User
	})
	return out
}

// ---------- phone-home watch ----------

type destRow struct {
	IP      string `json:"ip"`
	Port    int    `json:"port,omitempty"`
	Process string `json:"process,omitempty"` // program that opened the connection (ss -p)
	Owner   string `json:"owner,omitempty"`
	Country string `json:"country,omitempty"`
}
type phoneBlock struct {
	External     int       `json:"external"`
	Destinations []destRow `json:"destinations"`
}

// reProc pulls the first process out of `ss -p`'s users:(("name",pid=NNN,fd=NN)) field.
var reProc = regexp.MustCompile(`\(\("([^"]+)",pid=(\d+)`)

// phoneHome lists the external hosts the server itself reached OUT to — a live
// snapshot from `ss`, with the process that opened each connection. It's a
// snapshot, not a baseline, so we report destinations (and their process), not
// verdicts — a reverse shell / beacon shows up here.
func phoneHome() phoneBlock {
	out, err := exec.Command("ss", "-tunHp", "state", "established").Output()
	if err != nil {
		return phoneBlock{Destinations: []destRow{}}
	}
	return parsePhoneHome(out, listeningPortSet(), hostOwnIPs())
}

// parsePhoneHome is the pure core: given `ss -tunHp` output, the set of our
// listening service ports, and this host's own IPs, it returns only genuinely
// OUTBOUND connections to EXTERNAL hosts. Split out from the exec so it's testable.
//
// Direction: in a connection the client holds the ephemeral (high) port and the
// server holds the service port. So a row is INBOUND (skip) when we hold a
// service port — either it's in our listening set, or our local port is
// non-ephemeral while the peer's is ephemeral. Self-connections (peer is one of
// our own IPs) and private/loopback peers are dropped too.
func parsePhoneHome(ssOut []byte, listening map[int]bool, ownIPs map[string]bool) phoneBlock {
	pb := phoneBlock{Destinations: []destRow{}}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(ssOut), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		// established rows: f[3]=local addr:port, f[4]=peer addr:port.
		_, lps := splitHostPort(f[3])
		peerHost, pps := splitHostPort(f[4])
		if p := net.ParseIP(strings.Trim(peerHost, "[]")); p != nil {
			peerHost = p.String() // canonicalize (e.g. ::ffff:1.2.3.4 -> 1.2.3.4)
		}
		if peerHost == "" || isPrivateOrLocal(peerHost) || ownIPs[peerHost] {
			continue // loopback/private, or the box talking to itself
		}
		localPort, _ := strconv.Atoi(lps)
		peerPort, _ := strconv.Atoi(pps)
		if listening[localPort] {
			continue // inbound to one of our services
		}
		if isEphemeralPort(peerPort) && !isEphemeralPort(localPort) {
			continue // peer is the client (ephemeral), we hold the service port -> inbound
		}
		proc, _ := parseProc(line)
		key := peerHost + "|" + strconv.Itoa(peerPort) + "|" + proc
		if seen[key] {
			continue
		}
		seen[key] = true
		pb.Destinations = append(pb.Destinations, destRow{IP: peerHost, Port: peerPort, Process: proc})
	}
	pb.External = len(pb.Destinations)
	return pb
}

// isEphemeralPort reports whether p is in Linux's default ephemeral range, i.e. a
// client-side port rather than a service the host offers.
func isEphemeralPort(p int) bool { return p >= 32768 }

// parseProc extracts the owning process name + pid from an `ss -p` line.
func parseProc(line string) (string, int) {
	m := reProc.FindStringSubmatch(line)
	if m == nil {
		return "", 0
	}
	pid, _ := strconv.Atoi(m[2])
	return m[1], pid
}

// hostOwnIPs is the set of IP addresses bound to this host (all interfaces). The
// api runs network_mode:host, so this sees the real host IPs incl. the public one,
// letting us recognize (and drop) the box's connections to itself.
func hostOwnIPs() map[string]bool {
	ips := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			ips[ipnet.IP.String()] = true
		}
	}
	return ips
}

// listeningPortSet returns the local ports the host has services listening on, so
// phoneHome can tell inbound connections from outbound ones.
func listeningPortSet() map[int]bool {
	set := map[int]bool{}
	out, err := exec.Command("ss", "-tlnH").Output()
	if err != nil {
		return set
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		if _, lp := splitHostPort(f[3]); lp != "" { // f[3]=local for listening rows
			if p, _ := strconv.Atoi(lp); p > 0 {
				set[p] = true
			}
		}
	}
	return set
}

// ---------- persistence watch ----------

type persistBlock struct {
	PackageChanges7d int `json:"package_changes_7d"` // install/upgrade/remove events (7d), uncapped
	CronRecent       int `json:"cron_recent"`        // cron files changed in the last 7 days
}

func cronRecentChanges() int {
	out, err := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "sh", "-c",
		`find /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron -newermt '7 days ago' -type f 2>/dev/null | wc -l`).Output()
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

// ---------- small helpers ----------

func group1(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func isPrivateOrLocal(ip string) bool {
	p := net.ParseIP(strings.Trim(ip, "[]"))
	if p == nil {
		return true
	}
	return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsUnspecified()
}
