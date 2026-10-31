package fleet

// Session recordings, WebTerm-style. When a machine has recording on, EVERY interactive session on it
// is recorded — there is deliberately no per-session switch, so an operator can't turn it off right
// before doing something. Each session gets ONE continuous asciicast v2 file (<machine>-<session>.cast)
// that survives detach/reattach: it is appended to, and the timeline keeps running from the first
// attach. Output only — keystrokes are never stored (what you see is the shell's own echo, so a
// password typed at a no-echo prompt never lands here). Command markers ("m" events, from the shell
// integration hook) let the player jump to each command. Files are size-capped and deleted after
// console_record_days by a janitor. Files are encrypted at rest (console_record_crypt.go). Viewing: an
// operator sees their own recordings, an admin sees all, and every playback is audited. Only an admin
// can delete one by hand (re-authenticated every time, never while it is still being written, and the
// deletion itself stays in the audit log) — so an operator can't erase their own trail.

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

const recordDefaultDays = 30 // retention when console_record_days is unset/invalid

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
	Meta      recMeta `json:"motte"`
}

type consoleRecorder struct {
	mu     sync.Mutex
	f      *os.File
	aead   cipher.AEAD // this file's data key (see console_record_crypt.go)
	name   string      // file name, bound into every record
	seq    uint64      // next record's sequence number
	start  time.Time
	size   int64
	capped bool
	refs   int // interactive viewers attached that keep it open (guarded by agentConn.mu)
}

// openRecorder opens (or resumes) a session's encrypted recording. A new file gets a fresh key and the
// header; an existing one is appended to with the timeline continued from its header timestamp.
func openRecorder(m *Machine, session string, cols, rows int, meta recMeta) (*consoleRecorder, bool, error) {
	dir := recordDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, false, err
	}
	name := recordFileName(m.ID, session)
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		aead, err := newRecKey(name)
		if err != nil {
			return nil, false, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			deleteRecKey(name)
			return nil, false, err
		}
		rec := &consoleRecorder{f: f, aead: aead, name: name, start: time.Now()}
		title := "Session"
		if meta.Label > 0 {
			title = "Session " + strconv.Itoa(meta.Label)
		}
		b, _ := json.Marshal(recHeader{Version: 2, Width: cols, Height: rows, Timestamp: rec.start.Unix(), Title: title, Meta: meta})
		if err := rec.writeRecord(recMagic, append(b, '\n')); err != nil {
			if rec.f != nil {
				rec.f.Close()
			}
			os.Remove(path)
			deleteRecKey(name)
			return nil, false, err
		}
		return rec, true, nil
	} else if err != nil {
		return nil, false, err
	}
	// Resume: the header gives the timeline origin; count the records (sequence numbers continue)
	// and trim a half-written trailing record left by a crash so the next append stays readable.
	h, err := readRecHeader(path)
	if err != nil {
		return nil, false, err
	}
	aead, err := loadRecKey(name)
	if err != nil {
		return nil, false, err
	}
	rf, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	end, n, err := walkRecords(rf, nil)
	rf.Close()
	if err != nil {
		return nil, false, err
	}
	if err := os.Truncate(path, end); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, false, err
	}
	rec := &consoleRecorder{f: f, aead: aead, name: name, seq: n, start: time.Now(), size: end}
	if h.Timestamp > 0 {
		rec.start = time.Unix(h.Timestamp, 0)
	}
	rec.capped = rec.size >= helper.MaxRecordingBytes
	return rec, false, nil
}

// writeRecord seals one plaintext line as the next record and appends it (after prefix, used only
// for the file magic). Caller holds c.mu or owns c exclusively.
func (c *consoleRecorder) writeRecord(prefix, plain []byte) error {
	rec, err := sealRecord(c.aead, c.name, c.seq, plain)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, len(prefix)+len(rec))
	buf = append(append(buf, prefix...), rec...)
	n, err := c.f.Write(buf)
	c.size += int64(n)
	if err != nil {
		// A partial record may be on disk: stop writing (a later append would follow garbage); the
		// next open trims it.
		c.f.Close()
		c.f = nil
		return err
	}
	c.seq++
	return nil
}

func (c *consoleRecorder) event(kind, text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.capped || c.f == nil {
		return
	}
	b, _ := json.Marshal([]any{time.Since(c.start).Seconds(), kind, text})
	b = append(b, '\n')
	if c.size+int64(len(b))+64 > helper.MaxRecordingBytes { // 64: record framing + nonce + tag, with margin
		c.capped = true
		note, _ := json.Marshal([]any{time.Since(c.start).Seconds(), "m", "recording size limit reached — later output not recorded"})
		c.writeRecord(nil, append(note, '\n'))
		return
	}
	c.writeRecord(nil, b)
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

// recordMarker adds a marker to a session's recording (when it is being recorded).
func (a *agentConn) recordMarker(session, label string) {
	a.mu.Lock()
	r := a.recs[session]
	a.mu.Unlock()
	if r != nil {
		r.event("m", label)
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
// purgeRecordings deletes every recording of a machine and its key. The machine is identified from
// each file's header, never the filename (one machine id can be a prefix of another's).
func purgeRecordings(machineID string) {
	dir := recordDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !recNameRe.MatchString(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if h, err := readRecHeader(path); err == nil && h.Meta.MachineID == machineID && os.Remove(path) == nil {
			deleteRecKey(e.Name())
		}
	}
}

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
		if info, err := e.Info(); err == nil && (info.ModTime().Before(cutoff) || isPlainRecording(filepath.Join(dir, e.Name()), info)) {
			if os.Remove(filepath.Join(dir, e.Name())) == nil {
				deleteRecKey(e.Name())
				removed++
			}
		}
	}
	pruneRecKeys(dir)
	if removed > 0 {
		events.Audit("fleet", "console_record_purge", events.SeverityInfo, "", "",
			fmt.Sprintf("Deleted %d console recording(s) past the retention period", removed))
	}
}

// isPlainRecording spots an unencrypted recording left by a build before encryption at rest, so the
// janitor removes it now instead of keeping plaintext for the whole retention period. Files younger
// than a minute are skipped, so a recording being created is never mistaken for one.
func isPlainRecording(path string, info os.FileInfo) bool {
	if info.Size() < int64(len(recMagic)) || time.Since(info.ModTime()) < time.Minute {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, len(recMagic))
	if _, err := io.ReadFull(f, head); err != nil {
		return false
	}
	return !bytes.Equal(head, recMagic)
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
	// The machine it was recorded on, so a list across machines can play and delete each one.
	MachineID   string `json:"machine_id"`
	MachineName string `json:"machine_name"`
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

// handleConsoleRecordings lists the recordings the caller may see, newest first: one machine's with
// ?machine_id=, otherwise every machine in the caller's scope (the Sessions page).
// GET /api/fleet/console/recordings[?machine_id=]
func (s *Service) handleConsoleRecordings(w http.ResponseWriter, r *http.Request) {
	var p *router.Principal
	machines := map[string]Machine{}
	if r.URL.Query().Get("machine_id") != "" {
		caller, m, _, ok := s.recordingAccess(w, r)
		if !ok {
			return
		}
		p = caller
		machines[m.ID] = *m
	} else {
		if p = router.CurrentUser(r); p == nil {
			router.JSONError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		all, err := s.ListMachines()
		if err != nil {
			router.JSONError(w, "could not list machines", http.StatusInternalServerError)
			return
		}
		for _, m := range all {
			if !m.Revoked && scopeAllows(p, m) { // same set machineByID + recordingAccess allow
				machines[m.ID] = m
			}
		}
	}
	out := listRecordings(machines, p.UserID, auth.RoleAtLeast(p.Role, auth.RoleAdmin))
	router.JSON(w, map[string]any{"recordings": out, "retentionDays": int(recordRetention().Hours() / 24)})
}

// listRecordings returns the recordings of the given machines, newest first; a non-admin sees only
// their own. The machine comes from the header, never the filename (one id can prefix another's).
func listRecordings(machines map[string]Machine, userID int64, admin bool) []recordingInfo {
	dir := recordDir()
	entries, _ := os.ReadDir(dir)
	out := []recordingInfo{}
	for _, e := range entries {
		if e.IsDir() || !recNameRe.MatchString(e.Name()) {
			continue
		}
		h, err := readRecHeader(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		m, ok := machines[h.Meta.MachineID]
		if !ok || (!admin && h.Meta.UserID != userID) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		_, client, _ := strings.Cut(h.Meta.Session, "_")
		out = append(out, recordingInfo{
			Name: e.Name(), Title: h.Title, User: h.Meta.User, Started: h.Timestamp, Ended: info.ModTime().Unix(),
			Size: info.Size(), Live: isRecording(m.ID, h.Meta.Session), Capped: info.Size() >= helper.MaxRecordingBytes,
			Session: client, Width: h.Width, Height: h.Height, MachineID: m.ID, MachineName: m.Name,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ended > out[j].Ended })
	return out
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
	st, err := os.Stat(path)
	if err != nil {
		router.JSONError(w, "recording not found", http.StatusNotFound)
		return
	}
	data, err := decryptRecording(path)
	if err != nil {
		router.JSONError(w, "recording can't be read: "+err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("fleet", "console_recording_view", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Viewed recording %s of %s's session on %q", name, h.Meta.User, m.Name))
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, st.ModTime(), bytes.NewReader(data))
}

// handleConsoleRecordingDelete deletes one recording and its key (so leftover copies of the file can
// never be decrypted). Admin only, re-authenticated EVERY time (no grace window — erasing an audit
// trail is rarer and weightier than opening a console), refused while the session is still being
// recorded, and audited.
// POST /api/fleet/console/recording/delete {"machine_id","name","currentPassword","totpCode"}
func (s *Service) handleConsoleRecordingDelete(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	if p == nil || !auth.RoleAtLeast(p.Role, auth.RoleAdmin) {
		router.JSONError(w, "admin role required", http.StatusForbidden)
		return
	}
	var req struct {
		MachineID string `json:"machine_id"`
		Name      string `json:"name"`
		auth.StepUpCreds
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	m, err := s.machineByID(req.MachineID)
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return
	}
	if !scopeAllows(p, *m) {
		router.JSONError(w, "machine out of scope", http.StatusForbidden)
		return
	}
	if !recNameRe.MatchString(req.Name) || filepath.Base(req.Name) != req.Name {
		router.JSONError(w, "invalid recording name", http.StatusBadRequest)
		return
	}
	path := filepath.Join(recordDir(), req.Name)
	h, err := readRecHeader(path)
	if err != nil || h.Meta.MachineID != m.ID {
		router.JSONError(w, "recording not found", http.StatusNotFound)
		return
	}
	if !auth.RequireStepUp(w, r, req.StepUpCreds) {
		return
	}
	// Under the agent's lock, so a viewer can't reattach (reopening the file) between the live check
	// and the removal. The key goes first: even if the file removal fails, its content is unreadable.
	a := regGet(m.ID)
	if a != nil {
		a.mu.Lock()
	}
	err = nil
	if a != nil && a.recs[h.Meta.Session] != nil {
		err = errRecLive
	} else if err = deleteRecKey(req.Name); err == nil {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			err = rmErr
		}
	}
	if a != nil {
		a.mu.Unlock()
	}
	if errors.Is(err, errRecLive) {
		router.JSONError(w, "this session is still being recorded — stop the session first", http.StatusConflict)
		return
	}
	if err != nil {
		router.JSONError(w, "couldn't delete the recording: "+err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("fleet", "console_recording_delete", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Deleted recording %s of %s's session on %q (started %s)", req.Name, h.Meta.User, m.Name,
			time.Unix(h.Timestamp, 0).UTC().Format(time.RFC3339)))
	router.JSON(w, map[string]any{"ok": true})
}

var errRecLive = errors.New("recording is live")
