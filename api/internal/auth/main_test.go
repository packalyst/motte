package auth

import (
	"fmt"
	"os"
	"testing"

	"api/internal/database"
)

// TestMain opens the database once for the whole package run. database.Init is a process-wide
// singleton, so a per-test t.TempDir() left it pointing at the first test's folder after Go deleted
// it, and later tests failed at random ("user not found").
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "auth-test-")
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

// newTestService returns an auth service on the shared test database. Tests share it, so each
// uses its own usernames and never assumes the tables start empty.
func newTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return svc
}
