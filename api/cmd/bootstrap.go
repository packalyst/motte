package main

import (
	"log"
	"os"
	"strings"

	"api/internal/settings"
)

// bootstrapAdGuardPasswordFromFile hands the AdGuard admin password from setup to the panel:
// manage.sh writes the generated plaintext to a bootstrap file in the shared bind mount, together
// with its hash in AdGuard's own config. The panel encrypts it into its settings database, then
// deletes the file so the plaintext no longer sits on disk.
//
// The file is always the newest password (setup writes it alongside AdGuard's config), so it
// replaces a stored one: after a re-install over an existing database the panel would otherwise
// keep the old password while AdGuard has the new one, and the file would stay on disk. If saving
// fails, the file is kept so the next start retries. No file: nothing to do.
func bootstrapAdGuardPasswordFromFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	if pw := strings.TrimSpace(string(data)); pw != "" {
		if err := settings.SetSettingEncrypted("adguard_password", pw); err != nil {
			log.Printf("Warning: failed to bootstrap adguard_password from %s: %v", path, err)
			return
		}
		if u, _ := settings.GetSetting("adguard_username"); u == "" {
			_ = settings.SetSetting("adguard_username", "admin")
		}
	}

	if err := os.Remove(path); err != nil {
		log.Printf("Warning: bootstrap file %s could not be deleted: %v", path, err)
	} else {
		log.Printf("Bootstrapped adguard_password from %s (plaintext deleted from disk)", path)
	}
}
