package fleet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// The scan dialog: which folders a vulnerability scan skips (sent with "rescan"), and a folder
// picker that asks the agent for one folder's sub-folders at a time ("list-dirs"). The agent
// validates the same rules again; checking here keeps a bad request from ever being queued.
const (
	maxScanExcludes = 100
	maxScanPathLen  = 512
	dirsWait        = 10 * time.Second
	dirsPerUser     = 2 // folder listings one person can have waiting at once
)

// dirsBusy counts each user's listings in flight (handleListDirs).
var dirsBusy = struct {
	sync.Mutex
	n map[string]int
}{n: map[string]int{}}

// validScanPath accepts a clean absolute folder path (not "/" unless allowRoot), printable UTF-8,
// with no glob characters: Trivy reads --skip-dirs as globs, so "/*" would skip everything.
func validScanPath(p string, allowRoot bool) bool {
	if p == "" || len(p) > maxScanPathLen || !utf8.ValidString(p) || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return false
	}
	if p == "/" && !allowRoot {
		return false
	}
	return strings.IndexFunc(p, func(r rune) bool { return !unicode.IsPrint(r) || strings.ContainsRune(`*?[]{}\`, r) }) < 0
}

// scanProtected are where the system records its installed packages: leaving out one of
// them, or a folder holding one, would make a scan miss every OS package and look clean.
var scanProtected = []string{"/etc", "/var/lib/dpkg", "/var/lib/rpm", "/usr/lib/sysimage/rpm", "/lib/apk"}

// validExclude is a folder a scan may leave out.
func validExclude(p string) bool {
	if !validScanPath(p, false) {
		return false
	}
	for _, sys := range scanProtected {
		if sys == p || strings.HasPrefix(sys, p+"/") {
			return false
		}
	}
	return true
}

// validateCommandPayload checks the payloads of the commands whose agent-side effect depends on
// them: folder paths (rescan, list-dirs) and which tool to switch (set-tool).
func validateCommandPayload(ctype string, payload json.RawMessage) error {
	switch ctype {
	case "rescan":
		if len(payload) == 0 {
			return nil
		}
		var pl struct {
			Exclude []string `json:"exclude"`
		}
		if err := json.Unmarshal(payload, &pl); err != nil {
			return errors.New("bad scan request")
		}
		if len(pl.Exclude) > maxScanExcludes {
			return fmt.Errorf("too many excluded folders (max %d)", maxScanExcludes)
		}
		for _, p := range pl.Exclude {
			if !validExclude(p) {
				return fmt.Errorf("can't leave out %q: not a plain folder path, or it holds the system's package records", p)
			}
		}
	case "list-dirs":
		var pl struct {
			Path string `json:"path"`
		}
		if json.Unmarshal(payload, &pl) != nil || !validScanPath(pl.Path, true) {
			return errors.New("not a valid folder path")
		}
	case "set-tool":
		var pl struct {
			Tool    string `json:"tool"`
			Enabled *bool  `json:"enabled"`
		}
		if json.Unmarshal(payload, &pl) != nil || pl.Enabled == nil || !slices.Contains(machineTools, pl.Tool) {
			return errors.New("set-tool needs a tool (crowdsec, osquery or trivy) and enabled")
		}
	case "fix-packages":
		var pl struct {
			Packages []string `json:"packages"`
		}
		if json.Unmarshal(payload, &pl) != nil || len(pl.Packages) == 0 {
			return errors.New("fix-packages needs a list of packages")
		}
		if len(pl.Packages) > maxFixPackages {
			return fmt.Errorf("too many packages in one fix (max %d)", maxFixPackages)
		}
		for _, p := range pl.Packages {
			if len(p) > 200 || !pkgNameRe.MatchString(p) {
				return fmt.Errorf("%q is not a plain package name", p)
			}
		}
	case "set-dry-run":
		// The agent flips enforcement on this: it must say on or off explicitly.
		var pl struct {
			Enabled *bool `json:"enabled"`
		}
		if json.Unmarshal(payload, &pl) != nil || pl.Enabled == nil {
			return errors.New("set-dry-run needs enabled (true or false)")
		}
	case "sync-blocks":
		// The agent replaces its list with this one: a missing list must never read as empty
		// (clear-blocks is how a list is emptied).
		var pl struct {
			IPs *[]string `json:"ips"`
		}
		if json.Unmarshal(payload, &pl) != nil || pl.IPs == nil {
			return errors.New("sync-blocks needs the blocklist")
		}
	}
	return nil
}

// pkgNameRe is a package name the agent's apt/dnf/yum read as just a name (the agent checks the
// same rule): letters/digits first (never a flag), never a trailing '-' (apt: remove), an
// optional architecture suffix.
var pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*[A-Za-z0-9._+~](:[a-z0-9-]+)?$`)

// maxFixPackages bounds one targeted fix (the CVE drill-down selects a handful).
const maxFixPackages = 500

// scanExcludeList is a rescan payload's folders to skip; set is false when it gives no list (the
// agent then keeps the machine's saved one; any list, even empty, replaces it).
func scanExcludeList(payload json.RawMessage) (list []string, set bool) {
	var pl struct {
		Exclude *[]string `json:"exclude"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &pl) != nil || pl.Exclude == nil {
		return nil, false
	}
	return *pl.Exclude, true
}

// guardScanExcludes covers the one sensitive part of a rescan: its folders to skip are saved on
// the machine and apply to every later scan, so ADDING one hides that folder's findings for
// good. That takes an admin and a step-up; removing folders (scanning more) or rescanning with
// the same list stays an operator action. Any change to the list is audited with the folders.
func (s *Service) guardScanExcludes(r *http.Request, machineID string, payload json.RawMessage, pwd, totp string) (int, error) {
	next, set := scanExcludeList(payload)
	if !set {
		return 0, nil // the saved list stays as it is
	}
	var cur struct {
		ScanExclude []string `json:"scan_exclude"`
	}
	if raw, err := s.lastReport(machineID); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &cur)
	}
	var added, removed []string
	for _, p := range next {
		if !slices.Contains(cur.ScanExclude, p) {
			added = append(added, p)
		}
	}
	for _, p := range cur.ScanExclude {
		if !slices.Contains(next, p) {
			removed = append(removed, p)
		}
	}
	if len(added) > 0 {
		if p := router.CurrentUser(r); p == nil || (p.Role != "admin" && p.Role != "owner") {
			return http.StatusForbidden, errors.New("only an admin can add folders for scans to skip")
		}
		if status, err := s.verifyStepUp(r, "rescan (skip folders)", pwd, totp); err != nil {
			return status, err
		}
	}
	if len(added) > 0 || len(removed) > 0 {
		actor, _ := s.actingAdmin(r)
		events.Audit("fleet", "scan_excludes_changed", events.SeverityWarning, actor, helper.GetClientIP(r),
			fmt.Sprintf("Folders skipped by scans on %s changed: added %v, removed %v", machineID, added, removed))
	}
	return 0, nil
}

// machineTools are the agent tools a machine can turn on and off (set-tool).
var machineTools = []string{"crowdsec", "osquery", "trivy"}

// handleListDirs (POST /api/fleet/dirs {machine_id, path}) returns one folder's sub-folder names
// on a machine, for the scan dialog. It queues a list-dirs request, waits up to dirsWait for the
// agent's answer, then deletes the request: a picker opens many folders, and none of that
// belongs in the command log.
func (s *Service) handleListDirs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID string `json:"machine_id"`
		Path      string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil || req.MachineID == "" {
		router.JSONError(w, "machine_id and path required", http.StatusBadRequest)
		return
	}
	payload, _ := json.Marshal(map[string]string{"path": req.Path})
	if err := validateCommandPayload("list-dirs", payload); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.machineAllowed(r, req.MachineID) {
		router.JSONError(w, "your scope does not include this machine", http.StatusForbidden)
		return
	}
	if !linkOnline(req.MachineID) {
		router.JSONError(w, "the machine is offline", http.StatusConflict)
		return
	}
	actor, _ := s.actingAdmin(r)
	dirsBusy.Lock()
	if dirsBusy.n[actor] >= dirsPerUser {
		dirsBusy.Unlock()
		router.JSONError(w, "still waiting for the last folders; try again in a moment", http.StatusTooManyRequests)
		return
	}
	dirsBusy.n[actor]++
	dirsBusy.Unlock()
	defer func() {
		dirsBusy.Lock()
		if dirsBusy.n[actor]--; dirsBusy.n[actor] <= 0 {
			delete(dirsBusy.n, actor)
		}
		dirsBusy.Unlock()
	}()
	events.Audit("fleet", "list_dirs", events.SeverityInfo, actor, helper.GetClientIP(r),
		fmt.Sprintf("Listed the folders in %s on machine %s (scan dialog)", req.Path, req.MachineID))
	id, err := s.enqueue(req.MachineID, "list-dirs", payload, time.Minute)
	if err != nil {
		router.JSONError(w, "could not ask the machine", http.StatusInternalServerError)
		return
	}
	defer func() { _, _ = s.db.Exec(`DELETE FROM fleet_commands WHERE id = ?`, id) }()

	deadline := time.Now().Add(dirsWait)
	for time.Now().Before(deadline) {
		var status, result string
		if err := s.db.QueryRow(`SELECT status, COALESCE(result, '') FROM fleet_commands WHERE id = ?`, id).Scan(&status, &result); err != nil {
			break
		}
		switch status {
		case "done":
			var listing json.RawMessage
			if json.Unmarshal([]byte(result), &listing) != nil {
				router.JSONError(w, "the machine sent an unreadable answer", http.StatusBadGateway)
				return
			}
			router.JSON(w, listing)
			return
		case "error":
			router.JSONError(w, result, http.StatusUnprocessableEntity)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
	router.JSONError(w, "the machine didn't answer in time", http.StatusGatewayTimeout)
}
