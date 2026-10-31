package pwa

import (
	"fmt"
	"os"
	"testing"

	"api/internal/database"
)

// TestMain opens the database once for the whole package run: database.Init is a process-wide
// singleton, so a per-test t.TempDir() leaves it pointing at a folder Go already deleted once a
// second test asks for it. Tests share it and clean up their own rows.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pwa-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := 1
	if _, err := database.Init(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		code = m.Run()
		_ = database.Close()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
