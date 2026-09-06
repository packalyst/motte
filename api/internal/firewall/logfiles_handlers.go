package firewall

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"api/internal/helper"
	"api/internal/router"
)

// rotatedSuffix matches a rotated log's trailing ".1"/".2"… so the picker offers the live
// file, not its archives (a jail tails the current file).
var rotatedSuffix = regexp.MustCompile(`\.\d+$`)

type logFileEntry struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// handleGetLogFiles lists candidate log files on the host for the jail log-file picker:
// the real files under /var/log (one level deep) plus the panel's own app logs. It takes
// no input and only enumerates within read-allowed locations, returning files that exist.
// This is convenience only — ValidateLogFilePath remains the security gate on save, so a
// client still can't make a jail tail anything outside the allow-list.
func (s *Service) handleGetLogFiles(w http.ResponseWriter, r *http.Request) {
	seen := map[string]bool{}
	out := []logFileEntry{}
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		fi, err := os.Stat(path)
		if err != nil || fi.IsDir() {
			return
		}
		seen[path] = true
		out = append(out, logFileEntry{Path: path, Name: filepath.Base(path)})
	}

	// /var/log, one level deep — covers /var/log/auth.log and e.g. /var/log/nginx/access.log.
	const logDir = "/var/log"
	if entries, err := os.ReadDir(logDir); err == nil {
		for _, e := range entries {
			full := filepath.Join(logDir, e.Name())
			if e.IsDir() {
				if sub, err := os.ReadDir(full); err == nil {
					for _, se := range sub {
						if !se.IsDir() && isLogLike(se.Name()) {
							add(filepath.Join(full, se.Name()))
						}
					}
				}
				continue
			}
			if isLogLike(e.Name()) {
				add(full)
			}
		}
	}

	// The panel's own app logs live outside /var/log but inside the /data allow-list.
	add(helper.TurbotunnelsAuthLogPath())

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	router.JSON(w, map[string]any{"files": out})
}

// isLogLike keeps the picker to plausible *active* log files: *.log or a few well-known
// extensionless names, skipping compressed/rotated archives (auth.log.1, *.gz).
func isLogLike(name string) bool {
	switch name {
	case "syslog", "messages", "secure", "kern.log", "auth.log", "dpkg.log":
		return true
	}
	if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".xz") || strings.HasSuffix(name, ".zst") {
		return false
	}
	if rotatedSuffix.MatchString(name) {
		return false
	}
	return strings.HasSuffix(name, ".log")
}
