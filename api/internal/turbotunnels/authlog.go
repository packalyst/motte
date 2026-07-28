package turbotunnels

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"api/internal/helper"
)

// authLineRe matches the auth-failure marker the patched proxy (https.py) emits,
// anchored to a valid IPv4 so no other container log line can spoof it. Only the
// canonical "TURBOTUNNELS_AUTH_FAIL SRC=<ip>" substring is mirrored to the jail
// file — surrounding log text is never written — so unstructured subprocess
// stdout can't inject content into the jail's input.
var authLineRe = regexp.MustCompile(`TURBOTUNNELS_AUTH_FAIL SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// AuthLogPath is the api-owned file auth failures are mirrored to and that the
// 'turbotunnels' firewall jail monitors.
func AuthLogPath() string {
	return helper.TurbotunnelsAuthLogPath()
}

// StartAuthLogStreamer mirrors auth-failure markers from the turbotunnels
// container's logs into AuthLogPath so the firewall jail can ban brute-forcers.
//
// It polls with the Docker logs `since` parameter rather than holding a follow
// stream: polling is resilient to container restarts and request timeouts, and
// the jail already works on its own poll interval, so a ~10s cadence is ample.
// Runs until ctx is cancelled.
func StartAuthLogStreamer(ctx context.Context) {
	path := AuthLogPath()
	// Create the file up front so the jail monitor finds it at boot (a jail
	// whose log file is missing at startup is skipped and not retried).
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		f.Close()
	} else {
		log.Printf("turbotunnels: cannot create auth log %s: %v", path, err)
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
				if markers := fetchAuthMarkers(since); len(markers) > 0 {
					appendLines(path, markers)
				}
				since = next
			}
		}
	}()
}

// fetchAuthMarkers pulls container log lines produced since `since` (unix secs)
// and returns those containing the auth-failure marker.
func fetchAuthMarkers(since int64) []string {
	q := "/containers/" + ContainerName + "/logs?stdout=true&stderr=true&since=" + strconv.FormatInt(since, 10)
	resp, err := helper.DockerRequest("GET", q, nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil // container gone/not running — nothing to mirror
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(demuxDockerLog(body)))
	for scanner.Scan() {
		// Mirror only the canonical marker+IP, and only when it carries a valid
		// IPv4 — never the raw log line.
		if m := authLineRe.FindString(scanner.Text()); m != "" {
			out = append(out, m)
		}
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
