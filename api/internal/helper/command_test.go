package helper

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A command past its limit is killed and returns an error naming the timeout; one that finishes
// in time works as before, its exit status still readable.
func TestCommandTimeout(t *testing.T) {
	start := time.Now()
	err := commandWithin(200*time.Millisecond, "sleep", "30").Run()
	if err == nil || !strings.Contains(err.Error(), "no answer within") {
		t.Fatalf("a hung command returned %v, want a timeout error", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the hung command was stopped after %v", d)
	}

	out, err := Command("echo", "ok").Output()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("echo: %q, %v", out, err)
	}
	var exit *exec.ExitError
	if err := Command("false").Run(); !errors.As(err, &exit) {
		t.Fatalf("false: %v, want an exit error", err)
	}
}

// No code runs a system command without a time limit: plain exec.Command is refused outside this
// helper (exec.CommandContext carries its own limit and is allowed).
func TestNoUntimedCommands(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) && path != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "exec.Command(") {
				t.Errorf("%s:%d runs a command with no time limit; use helper.Command", path, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
