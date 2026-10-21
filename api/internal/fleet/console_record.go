package fleet

// Session recordings, WebTerm-style. When a machine has recording on, EVERY interactive session on it
// is recorded — there is deliberately no per-session switch, so an operator can't turn it off right
// before doing something. Each session gets ONE continuous asciicast v2 file (<machine>-<session>.cast)
// that survives detach/reattach: it is appended to, and the timeline keeps running from the first
// attach. Output only — keystrokes are never stored (what you see is the shell's own echo, so a
// password typed at a no-echo prompt never lands here). Command markers ("m" events, from the shell
// integration hook) let the player jump to each command. Files are size-capped and deleted after
// console_record_days by a janitor. Viewing: an operator sees their own recordings, an admin sees all,
// and every playback is audited. There is no delete endpoint on purpose — retention is the only way a
// recording goes away, so the trail can't be erased by hand.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/auth"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/settings"
)

const (
	recordMaxBytes    = 64 << 20 // per-session cap; past it, output is no longer recorded (marked once)
	recordDefaultDays = 30       // retention when console_record_days is unset/invalid
)

// recordDir is where session recordings are written. The default lives under DATA_DIR (the api's
// persistent volume) — a relative path resolved against the container's /app and was silently lost
// on every update/recreate.
func recordDir() string {
	d, _ := settings.GetSetting("console_record_dir")
	if d == "" {
		d = filepath.Join(helper.GetEnvOptional("DATA_DIR", "/data"), "console-recordings")
	}
	return d
}

func recordFileName(machineID, session string) string {
	return sanitize(machineID) + "-" + sanitize(session) + ".cast"
}

// recNameRe is the only shape a requested recording name may have (no separators, no "..").
var recNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+\.cast$`)

// recMeta is our block in the asciicast header (players ignore unknown keys). It is what listing and
// access control trust — never the filename, since one machine id can be a prefix of another's.
type recMeta struct {
	MachineID string `json:"machine_id"`
	Machine   string `json:"machine"`
	UserID    int64  `json:"user_id"`
	User      string `json:"user"`
	Session   string `json:"session"`
	Label     int    `json:"label"`
}

type recHeader struct {
	Version   int     `json:"version"`
	Width     int     `json:"width"`
	Height    int     `json:"height"`
	Timestamp int64   `json:"timestamp"`
	Title     string  `json:"title,omitempty"`
	Meta      recMeta `json:"wgadmin"`
}

// readRecHeader parses a recording's first line.
func readRecHeader(path string) (recHeader, error) {
	var h recHeader
	f, err := os.Open(path)
	if err != nil {
		return h, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return h, err
	}
	err = json.Unmarshal(line, &h)
	return h, err
}

type consoleRecorder struct {
	mu     sync.Mutex
	f      *os.File
	start  time.Time
	size   int64
	capped bool
	refs   int // interactive viewers attached that keep it open (guarded by agentConn.mu)
}

// openRecorder opens (or resumes) a session's recording. A new file gets the header; an existing one
// is appended to with the timeline continued from its header timestamp.
func openRecorder(m *Machine, session string, cols, rows int, meta recMeta) (*consoleRecorder, bool, error) {
	dir := recordDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, false, err
	}
	path := filepath.Join(dir, recordFileName(m.ID, session))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, false, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, false, err
	}
	rec := &consoleRecorder{f: f, start: time.Now(), size: st.Size()}
	if st.Size() == 0 {
		title := "Session"
		if meta.Label > 0 {
			title = "Session " + strconv.Itoa(meta.Label)
		}
		b, _ := json.Marshal(recHeader{Version: 2, Width: cols, Height: rows, Timestamp: rec.start.Unix(), Title: title, Meta: meta})
		n, _ := f.Write(append(b, '\n'))
		rec.size = int64(n)
		return rec, true, nil
	}
	if h, err := readRecHeader(path); err == nil && h.Timestamp > 0 {
		rec.start = time.Unix(h.Timestamp, 0)
	}
	rec.capped = rec.size >= recordMaxBytes
	return rec, false, nil
}

func (c *consoleRecorder) event(kind, text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.capped || c.f == nil {
		return
	}
	b, _ := json.Marshal([]any{time.Since(c.start).Seconds(), kind, text})
	b = append(b, '\n')
	if c.size+int64(len(b)) > recordMaxBytes {
		c.capped = true
		note, _ := json.Marshal([]any{time.Since(c.start).Seconds(), "m", "recording size limit reached — later output not recorded"})
		c.f.Write(append(note, '\n'))
		return
	}
	n, _ := c.f.Write(b)
	c.size += int64(n)
}

// writeOutput records one output frame (base64 from the agent, decoded so it replays correctly).
func (c *consoleRecorder) writeOutput(b64 string) {
	if data, err := base64.StdEncoding.DecodeString(b64); err == nil {
		c.event("o", string(data))
	}
}

// commandMarker records a shell-integration command ("exit|ms|cmd") as a seekable marker.
func (c *consoleRecorder) commandMarker(b64 string) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 || parts[2] == "" {
		return
	}
	label := parts[2]
	if parts[0] != "0" {
		label += "  (exit " + parts[0] + ")"
	}
	c.event("m", label)
}

func (c *consoleRecorder) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f != nil {
		c.f.Close()
		c.f = nil
	}
}

// attachRecorder starts (or joins) recording of a session for one interactive viewer.
func (a *agentConn) attachRecorder(m *Machine, session string, cols, rows int, p *router.Principal) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r := a.recs[session]; r != nil {
		r.refs++
		return
	}
	meta := recMeta{MachineID: m.ID, Machine: m.Name, UserID: p.UserID, User: p.Username, Session: session, Label: a.labels[session]}
	r, fresh, err := openRecorder(m, session, cols, rows, meta)
	if err != nil {
		events.Audit("fleet", "console_record", events.SeverityWarning, p.Username, "",
			fmt.Sprintf("Recording FAILED to start for session %s on %q: %v", session, m.Name, err))
		return
	}
	r.refs = 1
	a.recs[session] = r
	if fresh {
		events.Audit("fleet", "console_record", events.SeverityInfo, p.Username, "",
			fmt.Sprintf("Recording console session %s on %q → %s", session, m.Name, recordFileName(m.ID, session)))
	}
}

// detachRecorder drops one viewer; the file closes when the last one leaves (it reopens, appending,
// on the next attach).
func (a *agentConn) detachRecorder(session string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.recs[session]
	if r == nil {
		return
	}
	if r.refs--; r.refs <= 0 {
		delete(a.recs, session)
		r.close()
	}
}

// recordFrame tees one agent frame into its session's recording (once per frame, not per viewer).
func (a *agentConn) recordFrame(f consoleFrame) {
	if f.T != "data" && f.T != "command" {
		return
	}
	a.mu.Lock()
	r := a.recs[f.Session]
	a.mu.Unlock()
	if r == nil {
		return
	}
	if f.T == "data" {
		r.writeOutput(f.Data)
	} else {
		r.commandMarker(f.Data)
	}
}

// closeRecorder ends a session's recording outright (shell exited / channel dropped).
func (a *agentConn) closeRecorder(session string) {
	a.mu.Lock()
	r := a.recs[session]
	delete(a.recs, session)
	a.mu.Unlock()
	if r != nil {
		r.close()
	}
}

// isRecording reports whether a recording file is currently being written (session live + attached).
func isRecording(machineID, session string) bool {
	a := regGet(machineID)
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recs[session] != nil
}

// ---- retention -------------------------------------------------------------------------------------

func recordRetention() time.Duration {
	days := recordDefaultDays
	if v, _ := settings.GetSetting("console_record_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	return time.Duration(days) * 24 * time.Hour
}

// sweepRecordings deletes recordings untouched for longer than the retention. A recording being
// written is touched on every frame, so it is never old enough to match.
func sweepRecordings() {
	dir := recordDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-recordRetention())
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cast") {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			if os.Remove(filepath.Join(dir, e.Name())) == nil {
				removed++
			}
		}
	}
	if removed > 0 {
		events.Audit("fleet", "console_record_purge", events.SeverityInfo, "", "",
			fmt.Sprintf("Deleted %d console recording(s) past the retention period", removed))
	}
}

var recordJanitorOnce sync.Once

// startRecordJanitor runs the retention sweep now and every 6 hours, for the life of the process.
func startRecordJanitor() {
	recordJanitorOnce.Do(func() {
		go func() {
			sweepRecordings()
			t := time.NewTicker(6 * time.Hour)
			defer t.Stop()
			for range t.C {
				sweepRecordings()
			}
		}()
	})
}

// ---- HTTP: list + fetch -------------------------------------------------------------------------------

type recordingInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	User    string `json:"user"`
	Started int64  `json:"started"`
	Ended   int64  `json:"ended"` // last write (mtime)
	Size    int64  `json:"size"`
	Live    bool   `json:"live"`
	Capped  bool   `json:"capped"`
	Session string `json:"session"` // client-facing id (no owner prefix)
	Width   int    `json:"width"`
	Height  int    `json:"height"`
}

// recordingAccess resolves the caller + machine and decides whether they may see a recording:
// operator+ in scope; an operator only their own, an admin everyone's.
func (s *Service) recordingAccess(w http.ResponseWriter, r *http.Request) (*router.Principal, *Machine, bool, bool) {
	p := router.CurrentUser(r)
	if p == nil {
		router.JSONError(w, "unauthorized", http.StatusUnauthorized)
		return nil, nil, false, false
	}
	m, err := s.machineByID(r.URL.Query().Get("machine_id"))
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return nil, nil, false, false
	}
	if !scopeAllows(p, *m) {
		router.JSONError(w, "machine out of scope", http.StatusForbidden)
		return nil, nil, false, false
	}
	return p, m, auth.RoleAtLeast(p.Role, auth.RoleAdmin), true
}

// handleConsoleRecordings lists a machine's recordings the caller may see, newest first.
// GET /api/fleet/console/recordings?machine_id=
func (s *Service) handleConsoleRecordings(w http.ResponseWriter, r *http.Request) {
	p, m, admin, ok := s.recordingAccess(w, r)
	if !ok {
		return
	}
	dir := recordDir()
	entries, _ := os.ReadDir(dir)
	out := []recordingInfo{}
	for _, e := range entries {
		if e.IsDir() || !recNameRe.MatchString(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		h, err := readRecHeader(path)
		if err != nil || h.Meta.MachineID != m.ID {
			continue // other machine (trust the header, never a filename prefix)
		}
		if !admin && h.Meta.UserID != p.UserID {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		_, client, _ := strings.Cut(h.Meta.Session, "_")
		out = append(out, recordingInfo{
			Name: e.Name(), Title: h.Title, User: h.Meta.User, Started: h.Timestamp, Ended: info.ModTime().Unix(),
			Size: info.Size(), Live: isRecording(m.ID, h.Meta.Session), Capped: info.Size() >= recordMaxBytes,
			Session: client, Width: h.Width, Height: h.Height,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ended > out[j].Ended })
	router.JSON(w, map[string]any{"recordings": out, "retentionDays": int(recordRetention().Hours() / 24)})
}

// handleConsoleRecording streams one recording (.cast) for in-app playback or download. Audited.
// GET /api/fleet/console/recording?machine_id=&name=
func (s *Service) handleConsoleRecording(w http.ResponseWriter, r *http.Request) {
	p, m, admin, ok := s.recordingAccess(w, r)
	if !ok {
		return
	}
	name := r.URL.Query().Get("name")
	if !recNameRe.MatchString(name) || filepath.Base(name) != name {
		router.JSONError(w, "invalid recording name", http.StatusBadRequest)
		return
	}
	path := filepath.Join(recordDir(), name)
	h, err := readRecHeader(path)
	if err != nil || h.Meta.MachineID != m.ID {
		router.JSONError(w, "recording not found", http.StatusNotFound)
		return
	}
	if !admin && h.Meta.UserID != p.UserID {
		router.JSONError(w, "recording not found", http.StatusNotFound) // don't confirm someone else's exists
		return
	}
	f, err := os.Open(path)
	if err != nil {
		router.JSONError(w, "recording not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	events.Audit("fleet", "console_recording_view", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Viewed recording %s of %s's session on %q", name, h.Meta.User, m.Name))
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, st.ModTime(), f)
}
