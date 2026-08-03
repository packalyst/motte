package turbotunnels

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"api/internal/database"
	"api/internal/helper"
)

// Markers the patched proxy (https.py) emits, both anchored so no other
// container log line can spoof them:
//   - AUTH_FAIL: a failed proxy authentication (fed to the firewall jail).
//   - CONN:      an authenticated connection (recorded in the logs table).
var (
	authLineRe = regexp.MustCompile(`TURBOTUNNELS_AUTH_FAIL SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?: USER=(\S+))?`)
	connLineRe = regexp.MustCompile(`TURBOTUNNELS_CONN SRC=(\S+) USER=(\S+) DST=(\S+) DPORT=(\d+)`)
)

// AuthLogPath is the api-owned file auth failures are mirrored to and that the
// 'turbotunnels' firewall jail monitors.
func AuthLogPath() string {
	return helper.TurbotunnelsAuthLogPath()
}

// StartLogStreamer mirrors the proxy's log markers out of the container:
//   - auth failures → AuthLogPath (so the firewall jail can ban brute-forcers),
//   - authenticated connections → the logs table (so they appear on the Logs
//     page as outbound traffic tagged 'turbotunnels').
//
// It polls with the Docker logs `since` parameter rather than holding a follow
// stream: polling is resilient to container restarts and request timeouts. Runs
// until ctx is cancelled.
func StartLogStreamer(ctx context.Context) {
	path := AuthLogPath()
	// Create the file up front so the jail monitor finds it at boot (a jail
	// whose log file is missing at startup is skipped and not retried).
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		f.Close()
	} else {
		log.Printf("turbotunnels: cannot create auth log %s: %v", path, err)
	}

	db, err := database.GetDB()
	if err != nil {
		log.Printf("turbotunnels: log streamer has no DB, connection logging disabled: %v", err)
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		since := time.Now().Unix()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				next := time.Now().Unix()
				processLogLines(fetchLogLines(since), path, db)
				since = next
			}
		}
	}()
}

// processLogLines classifies each container log line: auth-failure markers are
// appended to the jail file, connection markers are inserted into the logs table.
func processLogLines(lines []string, jailPath string, db *database.DB) {
	var authMarkers []string
	for _, line := range lines {
		if am := authLineRe.FindStringSubmatch(line); am != nil {
			// Mirror to the jail file (the SRC drives the ban)...
			authMarkers = append(authMarkers, am[0])
			// ...and record the failed attempt as a blocked proxy log so it
			// shows on the Logs page and counts toward the tunnel's failures.
			if db != nil {
				insertFailLog(db, am[1], am[2])
			}
			continue
		}
		if db != nil {
			if cm := connLineRe.FindStringSubmatch(line); cm != nil {
				insertConnLog(db, cm[1], cm[2], cm[3], cm[4])
			}
		}
	}
	if len(authMarkers) > 0 {
		appendLines(jailPath, authMarkers)
	}
}

// insertFailLog records one failed proxy authentication as a blocked 'proxy'
// log row. USER is the target tunnel's username (known even though the client's
// credentials were wrong), so the failure attributes to the right tunnel.
func insertFailLog(db *database.DB, srcIP, user string) {
	if isInternalSource(srcIP) {
		return
	}
	_, err := db.Exec(`
		INSERT INTO logs (
			logs_timestamp, logs_type, logs_src_ip, logs_protocol, logs_status, logs_service
		) VALUES (?, 'proxy', ?, 'http', 'blocked', ?)`,
		time.Now(), srcIP, user)
	if err != nil {
		log.Printf("turbotunnels: failed to insert auth-fail log: %v", err)
	}
}

// insertConnLog records one authenticated proxy connection as a 'proxy' log
// row, so it shows up on the Logs page. The authenticating tunnel username is
// stored in logs_service (the 'proxy' type already identifies these as
// turbotunnels). The destination host goes to logs_domain; if it is a literal
// IP it is also stored as dest_ip so country lookup works.
// isInternalSource reports whether srcIP is on the internal docker network,
// where the panel's own health probes (e.g. SOCKS5 tests) originate — so they
// aren't recorded as real proxy usage. HTTP probes are already excluded by the
// X-TT-Test header; this covers SOCKS5, which has no such header.
func isInternalSource(srcIP string) bool {
	_, ipnet, err := net.ParseCIDR(helper.GetEnvOptional("DOCKER_SUBNET", "172.18.0.0/24"))
	if err != nil {
		return false
	}
	ip := net.ParseIP(srcIP)
	return ip != nil && ipnet.Contains(ip)
}

func insertConnLog(db *database.DB, srcIP, user, host, portStr string) {
	if isInternalSource(srcIP) {
		return
	}
	port, _ := strconv.Atoi(portStr)
	destIP := ""
	if net.ParseIP(host) != nil {
		destIP = host
	}
	_, err := db.Exec(`
		INSERT INTO logs (
			logs_timestamp, logs_type, logs_src_ip, logs_dest_ip,
			logs_dest_port, logs_protocol, logs_domain, logs_status, logs_service
		) VALUES (?, 'proxy', ?, ?, ?, 'http', ?, 'allowed', ?)`,
		time.Now(), srcIP, destIP, port, host, user)
	if err != nil {
		log.Printf("turbotunnels: failed to insert connection log: %v", err)
	}
}

// fetchLogLines returns container log lines produced since `since` (unix secs).
func fetchLogLines(since int64) []string {
	q := "/containers/" + ContainerName + "/logs?stdout=true&stderr=true&since=" + strconv.FormatInt(since, 10)
	resp, err := helper.DockerRequest("GET", q, nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil // container gone/not running — nothing to mirror
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(demuxDockerLog(body)))
	for scanner.Scan() {
		out = append(out, scanner.Text())
	}
	return out
}

// appendLines appends lines to the auth log (best-effort).
func appendLines(path string, lines []string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
}
