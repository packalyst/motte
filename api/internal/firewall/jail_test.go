package firewall

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"api/internal/bounded"
	"api/internal/helper"
)

// An address with maxRetry matches within findTime is banned and forgotten; one below it (older
// matches don't count) stays counted.
func TestJailCountsAndBans(t *testing.T) {
	s := lockoutService(t)
	s.blockCache = &blockCache{ttl: 10 * time.Second}
	dir := t.TempDir()
	saved := helper.AllowedLogDirs
	helper.AllowedLogDirs = append([]string{dir}, saved...)
	t.Cleanup(func() { helper.AllowedLogDirs = saved })

	logFile := filepath.Join(dir, "auth.log")
	lines := strings.Repeat("Failed password from 192.0.2.60\n", 3) + strings.Repeat("Failed password from 192.0.2.61\n", 2)
	if err := os.WriteFile(logFile, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	attempts := bounded.New[string, []time.Time](helper.MaxJailTracked, bounded.DropOldest)
	// A hit from before findTime doesn't count: 192.0.2.61's two new ones stay under maxRetry.
	attempts.Update("192.0.2.61", time.Now(), func(times *[]time.Time, _ bool) time.Time {
		*times = []time.Time{time.Now().Add(-time.Hour)}
		return time.Now().Add(time.Minute)
	})
	re := regexp.MustCompile(`Failed password from (\d+\.\d+\.\d+\.\d+)`)
	s.processJailLogFile("sshd", logFile, re, attempts, 0, 1, 3, 600, 0)

	if got := storedValues(t, s); len(got) != 1 || !got["192.0.2.60"] {
		t.Fatalf("banned %v, want only 192.0.2.60", got)
	}
	if _, ok := attempts.Get("192.0.2.60", time.Now()); ok {
		t.Error("a banned address is still counted")
	}
	if times, ok := attempts.Get("192.0.2.61", time.Now()); !ok || len(times) != 2 {
		t.Errorf("192.0.2.61 counted %d times, want 2", len(times))
	}
}
