package fleet

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"api/internal/router"
)

func castLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func newRecAgent() *agentConn {
	return &agentConn{bridges: map[string][]*consoleBridge{}, owners: map[string]int64{}, labels: map[string]int{}, recs: map[string]*consoleRecorder{}}
}

// One session = one continuous file: a second viewer joins the same recorder, every frame is written
// exactly once (not once per viewer), and a reattach appends to the same file with the header intact.
func TestRecordingOneFilePerSessionAppendsAcrossReattach(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
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
	t.Setenv("DATA_DIR", t.TempDir())
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
	t.Setenv("DATA_DIR", t.TempDir())
	dir := recordDir()
	os.MkdirAll(dir, 0o750)
	old, fresh := filepath.Join(dir, "old.cast"), filepath.Join(dir, "fresh.cast")
	os.WriteFile(old, []byte("{}\n"), 0o640)
	os.WriteFile(fresh, []byte("{}\n"), 0o640)
	past := time.Now().Add(-recordRetention() - time.Hour)
	os.Chtimes(old, past, past)
	sweepRecordings()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("expired recording should be deleted")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("recent recording must be kept")
	}
}
