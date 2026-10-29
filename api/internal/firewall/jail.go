package firewall

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"

	"api/internal/bounded"
	"api/internal/helper"
	"api/internal/routines"
)

// runJailMonitors starts monitors for all enabled jails
func (s *Service) runJailMonitors() {
	rows, err := s.db.Query("SELECT id, name, log_file, filter_regex, max_retry, find_time, ban_time, last_log_pos FROM jails WHERE enabled = 1")
	if err != nil {
		log.Printf("Failed to load jails: %v", err)
		return
	}
	defer rows.Close()

	var jails []jailConfig

	for rows.Next() {
		var j jailConfig
		if err := rows.Scan(&j.ID, &j.Name, &j.LogFile, &j.FilterRegex, &j.MaxRetry, &j.FindTime, &j.BanTime, &j.LastLogPos); err != nil {
			log.Printf("Warning: failed to scan jail: %v", err)
			continue
		}
		jails = append(jails, j)
	}

	for _, jail := range jails {
		s.startJailMonitor(jail.ID, jail.Name, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.LastLogPos)
	}

	routines.RegisterDaemon("firewall-jails", "Brute-force jail engine: one monitor per enabled jail")
	log.Printf("Started %d jail monitors", len(jails))
}

// startJailMonitor starts a jail monitor with its own cancellable context
func (s *Service) startJailMonitor(jailID int64, name, logFile, filterRegex string, maxRetry, findTime, banTime int, lastLogPos int64) {
	// Validate BEFORE registering, so a jail that can't run never leaves a stale monitor
	// entry pointing at an already-returned goroutine. (No lock held during file I/O.)
	if err := helper.ValidateLogFilePath(logFile); err != nil {
		log.Printf("Jail %s: invalid log file path %s: %v", name, logFile, err)
		return
	}
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		log.Printf("Jail %s: log file %s not found, skipping", name, logFile)
		return
	}

	ctx, cancel := context.WithCancel(s.ctx)

	// Stop-existing + register-new atomically under one lock. Doing stop and register as
	// two separately-locked steps let a concurrent start for the same jail slip in between,
	// leaving an un-cancellable monitor goroutine leaked.
	s.jailMutex.Lock()
	if existing, ok := s.jailMonitors[jailID]; ok {
		log.Printf("Stopping jail monitor: %s (ID: %d)", existing.name, jailID)
		existing.cancel()
	}
	s.jailMonitors[jailID] = &jailMonitor{
		cancel: cancel,
		name:   name,
	}
	s.jailMutex.Unlock()

	go s.monitorJailWithContext(ctx, jailID, name, logFile, filterRegex, maxRetry, findTime, banTime, lastLogPos)
}

// stopJailMonitor stops a running jail monitor
func (s *Service) stopJailMonitor(jailID int64) {
	s.jailMutex.Lock()
	defer s.jailMutex.Unlock()

	if monitor, exists := s.jailMonitors[jailID]; exists {
		log.Printf("Stopping jail monitor: %s (ID: %d)", monitor.name, jailID)
		monitor.cancel()
		delete(s.jailMonitors, jailID)
	}
}

// restartJailMonitor restarts a jail monitor by reading its config from DB
func (s *Service) restartJailMonitor(jailID int64) {
	var j jailConfig
	err := s.db.QueryRow(`SELECT id, name, log_file, filter_regex, max_retry, find_time, ban_time, last_log_pos, enabled
		FROM jails WHERE id = ?`, jailID).Scan(
		&j.ID, &j.Name, &j.LogFile, &j.FilterRegex, &j.MaxRetry, &j.FindTime, &j.BanTime, &j.LastLogPos, &j.Enabled)
	if err != nil {
		log.Printf("Failed to load jail %d for restart: %v", jailID, err)
		return
	}

	s.stopJailMonitor(jailID)

	if j.Enabled {
		s.startJailMonitor(j.ID, j.Name, j.LogFile, j.FilterRegex, j.MaxRetry, j.FindTime, j.BanTime, j.LastLogPos)
		log.Printf("Restarted jail monitor: %s", j.Name)
	}
}

// monitorJailWithContext monitors a log file for the jail with a cancellable context
func (s *Service) monitorJailWithContext(ctx context.Context, jailID int64, name, logFile, filterRegex string, maxRetry, findTime, banTime int, lastLogPos int64) {
	// Log path + existence are validated in startJailMonitor before registration.
	log.Printf("Starting jail monitor: %s (file: %s, maxRetry: %d, findTime: %ds, banTime: %ds)",
		name, logFile, maxRetry, findTime, banTime)

	ticker := time.NewTicker(time.Duration(s.config.JailCheckInterval) * time.Second)
	defer ticker.Stop()

	// Compile (not MustCompile): create/update validate the pattern, but a bad value
	// reaching here out-of-band (migration, direct DB edit) must not panic-crash the
	// process — log and stop just this monitor instead.
	regex, err := regexp.Compile(filterRegex)
	if err != nil {
		log.Printf("jail %s: invalid filter regex %q, monitor not started: %v", name, filterRegex, err)
		return
	}
	ipAttempts := bounded.New[string, []time.Time](maxJailTracked, bounded.DropOldest)

	if lastLogPos == 0 {
		if stat, err := os.Stat(logFile); err == nil {
			lastLogPos = stat.Size()
			s.db.Exec("UPDATE jails SET last_log_pos = ? WHERE id = ?", lastLogPos, jailID)
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("Jail monitor %s stopping (context cancelled)", name)
			return
		case <-ticker.C:
			lastLogPos = s.processJailLogFile(name, logFile, regex, ipAttempts, lastLogPos, jailID, maxRetry, findTime, banTime)
		}
	}
}

// maxJailTracked caps the addresses one jail counts at once. Past it the least recently seen one
// is forgotten (a log line can't be refused, and the newest attackers matter most).
const maxJailTracked = 100_000

// processJailLogFile processes a jail log file and returns the new position. ipAttempts holds each
// address's matches within findTime.
func (s *Service) processJailLogFile(name, logFile string, regex *regexp.Regexp, ipAttempts *bounded.Map[string, []time.Time], lastLogPos int64, jailID int64, maxRetry, findTime, banTime int) int64 {
	// Validate log file path to prevent path injection
	if err := helper.ValidateLogFilePath(logFile); err != nil {
		return lastLogPos
	}

	file, err := os.Open(logFile)
	if err != nil {
		return lastLogPos
	}
	defer file.Close()

	stat, _ := file.Stat()
	currentSize := stat.Size()

	// File rotated?
	if currentSize < lastLogPos {
		lastLogPos = 0
	}

	file.Seek(lastLogPos, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := regex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		srcIP := matches[1]

		if s.isIgnoredIP(srcIP) || s.isIPBlocked(srcIP) {
			continue
		}

		// For portscan jail, skip WireGuard port
		if name == "portscan" && len(matches) >= 3 {
			port, _ := strconv.Atoi(matches[2])
			if port == s.config.WgPort {
				continue
			}
		}

		destPort := 0
		if len(matches) >= 3 {
			destPort, _ = strconv.Atoi(matches[2])
		}
		s.recordAttempt(srcIP, destPort, "tcp", name, "blocked")

		// Keep this address's matches within findTime; once there are maxRetry, ban it and
		// forget them.
		now := time.Now()
		window := time.Duration(findTime) * time.Second
		hits := 0
		ipAttempts.Update(srcIP, now, func(times *[]time.Time, _ bool) time.Time {
			recent := (*times)[:0]
			for _, t := range *times {
				if t.After(now.Add(-window)) {
					recent = append(recent, t)
				}
			}
			*times = append(recent, now)
			if hits = len(*times); hits >= maxRetry {
				return now
			}
			return now.Add(window)
		})
		if hits >= maxRetry {
			s.blockIP(srcIP, name, fmt.Sprintf("Auto-blocked: %d attempts in %ds", hits, findTime), banTime)
		}
	}

	s.db.Exec("UPDATE jails SET last_log_pos = ? WHERE id = ?", currentSize, jailID)
	return currentSize
}

// ensureDefaultJails inserts default jails and ports if they don't exist
func (s *Service) ensureDefaultJails() error {
	sshPort := strconv.Itoa(helper.GetSSHPort())

	defaultJails := []Jail{
		{Name: "portscan", Enabled: true, LogFile: "/var/log/kern.log",
			FilterRegex: `FIREWALL_DROP:.*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)`,
			MaxRetry:    10, FindTime: 3600, BanTime: 2592000, Port: "all", Action: "drop"},
		{Name: "sshd", Enabled: true, LogFile: "/var/log/auth.log",
			FilterRegex: `Failed password.*from (\d+\.\d+\.\d+\.\d+)`,
			MaxRetry:    5, FindTime: 3600, BanTime: 2592000, Port: sshPort, Action: "drop"},
		// Bans clients that repeatedly fail auth against a turbotunnels proxy.
		// The api mirrors the proxy's "TURBOTUNNELS_AUTH_FAIL SRC=<ip>" markers
		// into this file (see turbotunnels.StartAuthLogStreamer).
		{Name: "turbotunnels", Enabled: true, LogFile: helper.TurbotunnelsAuthLogPath(),
			FilterRegex: `TURBOTUNNELS_AUTH_FAIL SRC=(\d+\.\d+\.\d+\.\d+)`,
			MaxRetry:    5, FindTime: 3600, BanTime: 2592000, Port: "all", Action: "drop"},
		// Bans sources the port-80 gate keeps dropping while Cloudflare-only is on (scanners
		// reaching the server directly); the panel writes the gate's drops to this file.
		{Name: "webgate", Enabled: true, LogFile: helper.WebGateLogPath(),
			FilterRegex: `WEBGATE_DROP SRC=(\d+\.\d+\.\d+\.\d+)`,
			MaxRetry:    webGateJailMaxRetry, FindTime: webGateJailFindTime, BanTime: webGateJailBanSeconds, Port: "all", Action: "drop"},
	}
	ensureWebGateLog()

	for _, jail := range defaultJails {
		s.db.Exec(`INSERT OR IGNORE INTO jails (name, enabled, log_file, filter_regex, max_retry, find_time, ban_time, port, action)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			jail.Name, jail.Enabled, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.Port, jail.Action)
	}

	s.db.Exec(`UPDATE jails SET port = ? WHERE name = 'sshd'`, sshPort)

	return nil
}
