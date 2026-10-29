package helper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Lines are appended; a file that reached the cap starts over instead of growing.
func TestAppendJailLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jail.log")
	if err := AppendJailLines(path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("nothing to write created the file")
	}
	AppendJailLines(path, []string{"A SRC=192.0.2.1", "A SRC=192.0.2.2"})
	AppendJailLines(path, []string{"A SRC=192.0.2.3"})
	if b, _ := os.ReadFile(path); string(b) != "A SRC=192.0.2.1\nA SRC=192.0.2.2\nA SRC=192.0.2.3\n" {
		t.Fatalf("appended %q", b)
	}

	if err := os.WriteFile(path, []byte(strings.Repeat("x", MaxJailFileBytes)), 0o640); err != nil {
		t.Fatal(err)
	}
	AppendJailLines(path, []string{"A SRC=192.0.2.4"})
	if b, _ := os.ReadFile(path); string(b) != "A SRC=192.0.2.4\n" {
		t.Fatalf("a full file wasn't started over: %d bytes", len(b))
	}
}
