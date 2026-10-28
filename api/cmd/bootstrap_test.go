package main

import (
	"os"
	"path/filepath"
	"testing"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/settings"
)

// TestBootstrapAdGuardPassword: the bootstrap file is the newest AdGuard password, so it replaces
// a stored one (a re-install over an existing database) and is always deleted afterwards.
func TestBootstrapAdGuardPassword(t *testing.T) {
	t.Setenv("ENCRYPTION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	helper.InitEncryption()
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSettingEncrypted("adguard_password", "synthetic-old"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), ".password.bootstrap")
	if err := os.WriteFile(path, []byte("synthetic-new\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	bootstrapAdGuardPasswordFromFile(path)

	if got, _ := settings.GetSettingEncrypted("adguard_password"); got != "synthetic-new" {
		t.Errorf("stored password %q, want the bootstrap file's", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("bootstrap file still on disk (stat: %v)", err)
	}

	// No file: nothing changes.
	bootstrapAdGuardPasswordFromFile(path)
	if got, _ := settings.GetSettingEncrypted("adguard_password"); got != "synthetic-new" {
		t.Errorf("without a file the password changed to %q", got)
	}
}
