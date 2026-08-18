package server

import (
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"api/internal/router"
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

// activeSessionCounts counts the sessions currently open, keyed by user+IP, so a
// historical login can be flagged "active" when a live session matches it. Using a
// count (not a bool) means N live sessions from the same user+IP mark the N most
// recent matching logins — not all of them.
func activeSessionCounts() map[string]int {
	counts := map[string]int{}
	for _, line := range runWho() {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		host := whoHost(line)
		if host == "" {
			continue
		}
		counts[f[0]+"\x00"+host]++
	}
	return counts
}

// markActiveLogins flags the still-connected logins. For each (user, IP) group it
// marks the k most-recent login events active, where k is that pair's live-session
// count from `who`. Best-effort: a `who` host shown as a name (reverse DNS) simply
// won't match an IP-based login, so it stays unflagged rather than mislabeled.
func markActiveLogins(recent []loginEvent, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	groups := map[string][]int{}
	for i, l := range recent {
		if l.IP == "" {
			continue
		}
		key := l.User + "\x00" + l.IP
		groups[key] = append(groups[key], i)
	}
	for key, idxs := range groups {
		k := counts[key]
		if k <= 0 {
			continue
		}
		sort.Slice(idxs, func(a, b int) bool { return recent[idxs[a]].When.After(recent[idxs[b]].When) })
		for n := 0; n < k && n < len(idxs); n++ {
			recent[idxs[n]].Active = true
		}
	}
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
