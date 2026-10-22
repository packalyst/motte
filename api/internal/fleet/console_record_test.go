package fleet

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// castLines decrypts a recording and returns its asciicast lines.
func castLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := decryptRecording(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// useRecordStore points recordings at a temp dir and a temp DB holding their keys.
func useRecordStore(t *testing.T) {
	t.Helper()
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("ENCRYPTION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	helper.InitEncryption()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "rec.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureSchema(db); err != nil {
		t.Fatal(err)
	}
	prev := recordDB
	recordDB = db
	t.Cleanup(func() { recordDB = prev; db.Close() })
}

func newRecAgent() *agentConn {
	return &agentConn{bridges: map[string][]*consoleBridge{}, owners: map[string]int64{}, labels: map[string]int{}, recs: map[string]*consoleRecorder{}}
}

// One session = one continuous file: a second viewer joins the same recorder, every frame is written
// exactly once (not once per viewer), and a reattach appends to the same file with the header intact.
func TestRecordingOneFilePerSessionAppendsAcrossReattach(t *testing.T) {
	useRecordStore(t)
	m := &Machine{ID: "m1", Name: "web-01", ConsoleRecord: true}
	p := &router.Principal{UserID: 7, Username: "alice"}
	a := newRecAgent()
	sess := "7_abc"
	out := func(s string) consoleFrame {
		return consoleFrame{T: "data", Session: sess, Data: base64.StdEncoding.EncodeToString([]byte(s))}
	}

	a.attachRecorder(m, sess, 80, 24, p)
	a.attachRecorder(m, sess, 80, 24, p) // second window on the same session
	a.recordFrame(out("hello\r\n"))
	a.recordFrame(consoleFrame{T: "command", Session: sess, Data: base64.StdEncoding.EncodeToString([]byte("1|12|cat .env"))})
	a.recordFrame(consoleFrame{T: "resize", Session: sess}) // not recorded
	a.detachRecorder(sess)
	if a.recs[sess] == nil {
		t.Fatal("recorder closed while a viewer is still attached")
	}
	a.detachRecorder(sess)
	if a.recs[sess] != nil {
		t.Fatal("recorder should close when the last viewer leaves")
	}

	a.attachRecorder(m, sess, 80, 24, p) // reattach later → same file, appended
	a.recordFrame(out("again\r\n"))
	a.closeRecorder(sess)

	path := filepath.Join(recordDir(), recordFileName(m.ID, sess))
	lines := castLines(t, path)
	if len(lines) != 4 { // header + "hello" + marker + "again"
		t.Fatalf("want 4 lines (header + 3 events), got %d: %v", len(lines), lines)
	}
	var h recHeader
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil || h.Version != 2 || h.Meta.MachineID != "m1" || h.Meta.UserID != 7 {
		t.Fatalf("bad header: %+v (%v)", h, err)
	}
	if !strings.Contains(lines[2], `"m"`) || !strings.Contains(lines[2], "cat .env  (exit 1)") {
		t.Errorf("command marker missing/wrong: %s", lines[2])
	}
	if strings.Count(strings.Join(lines, "\n"), "hello") != 1 {
		t.Error("output was recorded more than once (per viewer instead of per frame)")
	}
	matches, _ := filepath.Glob(filepath.Join(recordDir(), "*.cast"))
	if len(matches) != 1 {
		t.Errorf("want exactly one file for the session, got %v", matches)
	}
}

// Past the cap, output stops being recorded and a single marker says so.
func TestRecordingCap(t *testing.T) {
	useRecordStore(t)
	m := &Machine{ID: "m1", Name: "web-01"}
	r, _, err := openRecorder(m, "7_x", 80, 24, recMeta{MachineID: "m1"})
	if err != nil {
		t.Fatal(err)
	}
	r.size = recordMaxBytes - 10
	r.event("o", strings.Repeat("x", 100))
	r.event("o", "more")
	r.close()
	lines := castLines(t, filepath.Join(recordDir(), recordFileName("m1", "7_x")))
	last := lines[len(lines)-1]
	if !strings.Contains(last, "size limit") || strings.Contains(strings.Join(lines, ""), "more") {
		t.Fatalf("cap not enforced: %v", lines)
	}
}

// Requested names can never escape the recordings directory.
func TestRecordingNameValidation(t *testing.T) {
	for _, bad := range []string{"../x.cast", "a/b.cast", "x.txt", "..cast", "x.cast/..", ""} {
		if recNameRe.MatchString(bad) && filepath.Base(bad) == bad {
			t.Errorf("name %q must be rejected", bad)
		}
	}
	if !recNameRe.MatchString("m1-7_abc.cast") {
		t.Error("a real recording name must be accepted")
	}
}

// Retention removes only recordings untouched for longer than the window.
func TestRecordingRetentionSweep(t *testing.T) {
	useRecordStore(t)
	dir := recordDir()
	os.MkdirAll(dir, 0o750)
	old, fresh := filepath.Join(dir, "old.cast"), filepath.Join(dir, "fresh.cast")
	os.WriteFile(old, []byte("{}\n"), 0o640)
	os.WriteFile(fresh, []byte("{}\n"), 0o640)
	past := time.Now().Add(-recordRetention() - time.Hour)
	os.Chtimes(old, past, past)
	legacy := filepath.Join(dir, "legacy.cast") // plaintext from before encryption at rest
	os.WriteFile(legacy, []byte(`{"version":2}`+"\n"), 0o640)
	hourAgo := time.Now().Add(-time.Hour)
	os.Chtimes(legacy, hourAgo, hourAgo)
	sweepRecordings()
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Error("a leftover plaintext recording should be deleted right away")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("expired recording should be deleted")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("recent recording must be kept")
	}
}

// At rest the file holds no plaintext; it is bound to its name (a renamed/swapped file fails), a
// tampered byte fails, and without its key (deleted) it can't be read at all.
func TestRecordingEncryptedAtRest(t *testing.T) {
	useRecordStore(t)
	m := &Machine{ID: "m1", Name: "web-01"}
	r, _, err := openRecorder(m, "7_s", 80, 24, recMeta{MachineID: "m1", User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	r.event("o", "SECRET_TOKEN=hunter2\r\n")
	r.close()
	path := filepath.Join(recordDir(), recordFileName("m1", "7_s"))
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "alice") {
		t.Fatal("plaintext found in the recording file")
	}
	if got := strings.Join(castLines(t, path), "\n"); !strings.Contains(got, "hunter2") {
		t.Fatalf("decrypted recording lost its output: %s", got)
	}

	// Copied under another name (with that name's key in place) → integrity failure, not content.
	other := filepath.Join(recordDir(), "m1-7_other.cast")
	os.WriteFile(other, raw, 0o640)
	if _, err := newRecKey("m1-7_other.cast"); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptRecording(other); err == nil {
		t.Error("a recording must not decrypt under another file's name/key")
	}

	// Flipped byte in the last record → integrity failure.
	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 1
	os.WriteFile(path, bad, 0o640)
	if _, err := decryptRecording(path); err == nil {
		t.Error("a tampered recording must fail to decrypt")
	}

	// Key deleted → unreadable even though the file is still there.
	os.WriteFile(path, raw, 0o640)
	deleteRecKey(recordFileName("m1", "7_s"))
	if _, err := decryptRecording(path); err == nil {
		t.Error("a recording whose key was deleted must be unreadable")
	}
}

// A crash can leave a half-written last record; the reader ignores it and the next append trims it
// so everything after stays readable.
func TestRecordingTrimsTornTail(t *testing.T) {
	useRecordStore(t)
	m := &Machine{ID: "m1", Name: "web-01"}
	r, _, err := openRecorder(m, "7_t", 80, 24, recMeta{MachineID: "m1"})
	if err != nil {
		t.Fatal(err)
	}
	r.event("o", "first\r\n")
	r.close()
	path := filepath.Join(recordDir(), recordFileName("m1", "7_t"))
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o640)
	f.Write([]byte{0, 0, 1, 0, 9, 9}) // a length prefix promising 256 bytes, then 2
	f.Close()
	if lines := castLines(t, path); len(lines) != 2 {
		t.Fatalf("torn tail should be ignored, got %d lines", len(lines))
	}
	r, _, err = openRecorder(m, "7_t", 80, 24, recMeta{MachineID: "m1"})
	if err != nil {
		t.Fatal(err)
	}
	r.event("o", "second\r\n")
	r.close()
	got := strings.Join(castLines(t, path), "\n")
	if !strings.Contains(got, "first") || !strings.Contains(got, "second") {
		t.Fatalf("append after a torn tail lost data: %s", got)
	}
}

// Only admins can delete a recording; an operator (even the recording's owner) is refused before
// anything is looked up.
func TestRecordingDeleteAdminOnly(t *testing.T) {
	svc := newTestService(t)
	body := strings.NewReader(`{"machine_id":"m1","name":"m1-7_s.cast"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/fleet/console/recording/delete", body)
	req = req.WithContext(router.ContextWithPrincipal(req.Context(), &router.Principal{UserID: 7, Role: "operator", Username: "alice"}))
	w := httptest.NewRecorder()
	svc.handleConsoleRecordingDelete(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("operator delete: want 403, got %d", w.Code)
	}
}

// The list across machines keeps only the given (in-scope) machines, and an operator sees only
// their own recordings while an admin sees everyone's.
func TestListRecordingsScopeAndOwner(t *testing.T) {
	useRecordStore(t)
	rec := func(machine string, uid int64, sess string) {
		r, _, err := openRecorder(&Machine{ID: machine}, sess, 80, 24, recMeta{MachineID: machine, UserID: uid, Session: sess})
		if err != nil {
			t.Fatal(err)
		}
		r.close()
	}
	rec("m1", 7, "7_a")
	rec("m1", 8, "8_b")
	rec("m2", 7, "7_c")
	inScope := map[string]Machine{"m1": {ID: "m1", Name: "web-01"}}

	own := listRecordings(inScope, 7, false)
	if len(own) != 1 || own[0].MachineID != "m1" || own[0].MachineName != "web-01" || own[0].Session != "a" {
		t.Fatalf("operator: want only their own m1 recording, got %+v", own)
	}
	if all := listRecordings(inScope, 7, true); len(all) != 2 {
		t.Fatalf("admin: want both m1 recordings and none from m2, got %+v", all)
	}
}
