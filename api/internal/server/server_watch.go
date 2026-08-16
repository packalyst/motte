package server

import (
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
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
		inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(ts, tty)
	)`)
}

// runSudoWatcher polls the auth log for sudo failures, resolving each to its
// session IP while the session is still active, and persists it. Runs for the
// process lifetime.
func (s *Service) runSudoWatcher() {
	s.ensureSudoTable()
	s.scanSudoFailures()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for range tick.C {
		s.scanSudoFailures()
	}
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
	rows, err := s.db.Query(`SELECT ts, user, tty, ip, command FROM sudo_failures
		ORDER BY inserted_at DESC LIMIT 15`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var f sudoFail
		var ts string
		if rows.Scan(&ts, &f.User, &f.TTY, &f.IP, &f.Command) != nil {
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

// whoSessions maps an active session TTY (pts/2, tty1) to its source IP via `who`
// on the host. Local console sessions have no remote IP (skipped).
func whoSessions() map[string]string {
	m := map[string]string{}
	out, err := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "who").Output()
	if err != nil {
		if out, err = exec.Command("who").Output(); err != nil {
			return m
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if i := strings.LastIndex(line, "("); i >= 0 {
			host := strings.Trim(strings.TrimSpace(line[i:]), "()")
			if host != "" && !strings.HasPrefix(host, ":") { // skip local X display ":0"
				m[f[1]] = host
			}
		}
	}
	return m
}

// ---------- phone-home watch ----------

type destRow struct {
	IP      string `json:"ip"`
	Owner   string `json:"owner,omitempty"`
	Country string `json:"country,omitempty"`
}
type phoneBlock struct {
	External     int       `json:"external"`
	Destinations []destRow `json:"destinations"`
}

// phoneHome lists the external hosts the server itself reached OUT to — a live
// snapshot from `ss`. `ss` shows both directions, so we skip inbound connections
// (those whose local port is one of our listening service ports); what's left is
// outbound (we initiated), which is where a reverse shell / beacon shows up. It's
// a snapshot, not a baseline, so we report destinations, not verdicts.
func phoneHome() phoneBlock {
	pb := phoneBlock{Destinations: []destRow{}}
	out, err := exec.Command("ss", "-tunH", "state", "established").Output()
	if err != nil {
		return pb
	}
	listening := listeningPortSet()
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		// established rows (state pre-filtered): f[3]=local addr:port, f[4]=peer.
		if _, lp := splitHostPort(f[3]); lp != "" {
			if p, _ := strconv.Atoi(lp); listening[p] {
				continue // inbound connection to one of our services — not phone-home
			}
		}
		addr, _ := splitHostPort(f[4])
		if addr == "" || isPrivateOrLocal(addr) || seen[addr] {
			continue
		}
		seen[addr] = true
		pb.Destinations = append(pb.Destinations, destRow{IP: addr})
	}
	pb.External = len(pb.Destinations)
	return pb
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
	PackagesInstalled int `json:"packages_installed"`
	CronRecent        int `json:"cron_recent"` // cron files changed in the last 7 days
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
