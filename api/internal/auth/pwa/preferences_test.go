package pwa

import (
	"database/sql"
	"path/filepath"
	"testing"

	"api/internal/database"

	_ "github.com/mattn/go-sqlite3"
)

// Only known notification types are stored; anything else a client sends is dropped.
func TestUpdatePreferencesKnownKeysOnly(t *testing.T) {
	raw, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	if _, err := raw.Exec(`CREATE TABLE users_notification_preferences (id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL, pref_key TEXT NOT NULL, enabled BOOLEAN DEFAULT 1, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	s := &Service{db: &database.DB{DB: raw}}
	if err := s.UpdatePreferences(7, NotificationPreferences{"cert_expiry": false, "made_up": true, "<script>": true}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = raw.QueryRow(`SELECT COUNT(*) FROM users_notification_preferences WHERE user_id = 7`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d rows stored, want only the known key", n)
	}
	prefs, err := s.GetPreferences(7)
	if err != nil || prefs["cert_expiry"] || len(prefs) != len(PreferenceDefaults) {
		t.Fatalf("prefs %v (%v)", prefs, err)
	}
}
