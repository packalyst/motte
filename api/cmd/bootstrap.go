package main

import (
	"log"
	"os"
	"strings"

	"api/internal/settings"
)

// bootstrapAdGuardPasswordFromFile is a one-shot migration for first-install:
// manage.sh writes the generated plaintext AdGuard admin password to a
// bootstrap file inside the shared bind mount. On first boot, we consume it —
// encrypt it into wgap's settings DB — then delete the file so the plaintext
// no longer sits on disk.
//
// Idempotent: if the settings DB already has an adguard_password, or the
// bootstrap file is absent, this is a no-op.
func bootstrapAdGuardPasswordFromFile(path string) {
	if _, err := settings.GetSettingEncrypted("adguard_password"); err == nil {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	pw := strings.TrimSpace(string(data))
	if pw == "" {
		_ = os.Remove(path)
		return
	}

	if err := settings.SetSettingEncrypted("adguard_password", pw); err != nil {
		log.Printf("Warning: failed to bootstrap adguard_password from %s: %v", path, err)
		return
	}

	if u, _ := settings.GetSetting("adguard_username"); u == "" {
		_ = settings.SetSetting("adguard_username", "admin")
	}

	if err := os.Remove(path); err != nil {
		log.Printf("Warning: bootstrap file %s could not be deleted: %v", path, err)
	} else {
		log.Printf("Bootstrapped adguard_password from %s (plaintext deleted from disk)", path)
	}
}
