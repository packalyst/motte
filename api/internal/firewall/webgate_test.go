package firewall

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"api/internal/bounded"
	"api/internal/helper"
)

// The port-80 gate feed: refused to outside callers; "off" while Cloudflare-only is off; "on"
// plus the allowed sources while it's on.
func TestInternalWebGate(t *testing.T) {
	s := lockoutService(t)
	t.Setenv("TRAEFIK_CONTAINER_IP", "172.18.0.5")
	get := func(remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/internal/webgate", nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.HandleInternalWebGate(rec, r)
		return rec
	}
	if rec := get("203.0.113.7:41000"); rec.Code != http.StatusNotFound {
		t.Fatalf("public caller: %d", rec.Code)
	}
	set := func(v string) {
		if _, err := s.db.Exec(`INSERT INTO settings (key, value, encrypted) VALUES ('web_cloudflare_only', ?, 0)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, v); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { s.db.Exec(`DELETE FROM settings WHERE key = 'web_cloudflare_only'`) })
	set("off")
	if body := get("172.18.0.5:41000").Body.String(); body != "off\n" {
		t.Fatalf("off: %q", body)
	}
	set("on")
	body := get("172.18.0.5:41000").Body.String()
	if !strings.HasPrefix(body, "on\n") || !strings.Contains(body, "\n127.0.0.0/8\n") || !strings.Contains(body, "\n104.16.0.0/13\n") {
		t.Fatalf("on: %q", body)
	}
}

// Drop reports are taken only from Traefik's own address; public IPv4 sources are written to the
// jail file (capped per address), everything else ignored; the 'webgate' jail bans after three.
func TestInternalWebGateDrops(t *testing.T) {
	s := lockoutService(t)
	s.blockCache = &blockCache{ttl: 10 * time.Second}
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	t.Setenv("TRAEFIK_CONTAINER_IP", "172.18.0.3")
	saved := helper.AllowedLogDirs
	helper.AllowedLogDirs = append([]string{dir}, saved...)
	t.Cleanup(func() { helper.AllowedLogDirs = saved })
	logFile := filepath.Join(dir, "webgate.log")

	post := func(remote, method, body string) int {
		r := httptest.NewRequest(method, "/internal/webgate/drops", strings.NewReader(body))
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.HandleInternalWebGateDrops(rec, r)
		return rec.Code
	}
	report := "192.0.2.80 3\n192.0.2.81 1\n192.0.2.82 50\n10.8.0.5 9\n2001:db8::1 9\nnot-an-ip 3\n192.0.2.83 0\n192.0.2.84 x\n"
	for _, c := range []struct{ remote, method string }{
		{"172.18.0.9:5000", http.MethodPost},  // another container
		{"203.0.113.1:5000", http.MethodPost}, // outside
		{"172.18.0.3:5000", http.MethodGet},
	} {
		if code := post(c.remote, c.method, report); code != http.StatusNotFound {
			t.Fatalf("%s %s: %d", c.method, c.remote, code)
		}
	}
	if _, err := os.Stat(logFile); err == nil {
		t.Fatal("a refused report was written")
	}
	t.Setenv("TRAEFIK_CONTAINER_IP", "")
	if code := post("172.18.0.3:5000", http.MethodPost, report); code != http.StatusNotFound {
		t.Fatalf("accepted with no Traefik address configured: %d", code)
	}
	t.Setenv("TRAEFIK_CONTAINER_IP", "172.18.0.3")
	if code := post("172.18.0.3:5000", http.MethodPost, report); code != http.StatusNoContent {
		t.Fatalf("Traefik's report: %d", code)
	}
	b, _ := os.ReadFile(logFile)
	counts := map[string]int{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		counts[strings.TrimPrefix(l, webGateDropMarker)]++
	}
	want := map[string]int{"192.0.2.80": 3, "192.0.2.81": 1, "192.0.2.82": helper.MaxWebGateDropsPerIP}
	if len(counts) != len(want) {
		t.Fatalf("written %v, want %v", counts, want)
	}
	for ip, n := range want {
		if counts[ip] != n {
			t.Fatalf("written %v, want %v", counts, want)
		}
	}

	// The default jail, over that file: three drops ban, one doesn't.
	attempts := bounded.New[string, []time.Time](helper.MaxJailTracked, bounded.DropOldest)
	re := regexp.MustCompile(`WEBGATE_DROP SRC=(\d+\.\d+\.\d+\.\d+)`)
	s.processJailLogFile("webgate", logFile, re, attempts, 0, 1, helper.WebGateJailMaxRetry, helper.WebGateJailFindTime, helper.WebGateJailBanSeconds)
	got := storedValues(t, s)
	if !got["192.0.2.80"] || !got["192.0.2.82"] || got["192.0.2.81"] || len(got) != 2 {
		t.Fatalf("banned %v, want 192.0.2.80 and 192.0.2.82", got)
	}
}

// The firewall's startup creates the 'webgate' jail with its defaults, and its file, so the jail
// monitor finds it at boot.
func TestWebGateJailDefault(t *testing.T) {
	s := lockoutService(t)
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	if _, err := s.db.Exec(`DELETE FROM jails WHERE name = 'webgate'`); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureDefaultJails(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "webgate.log")); err != nil {
		t.Fatalf("jail file not created: %v", err)
	}
	var logFile, re string
	var enabled bool
	var maxRetry, findTime, banTime int
	if err := s.db.QueryRow(`SELECT enabled, log_file, filter_regex, max_retry, find_time, ban_time FROM jails WHERE name = 'webgate'`).
		Scan(&enabled, &logFile, &re, &maxRetry, &findTime, &banTime); err != nil {
		t.Fatal(err)
	}
	if !enabled || logFile != filepath.Join(dir, "webgate.log") || maxRetry != 3 || findTime != 600 || banTime != 86400 ||
		!regexp.MustCompile(re).MatchString(webGateDropMarker+"192.0.2.9") {
		t.Fatalf("webgate jail: enabled=%v file=%s re=%s %d/%d/%d", enabled, logFile, re, maxRetry, findTime, banTime)
	}
}
