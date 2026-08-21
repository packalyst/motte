package backup

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"api/internal/helper"

	_ "github.com/mattn/go-sqlite3"
)

// testDB spins up a sqlite DB with a couple of the real config tables and the
// encryption key wired, enough to exercise a full export→import round trip.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("ENCRYPTION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	helper.InitEncryption()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`
		CREATE TABLE vpn_clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			ip TEXT NOT NULL UNIQUE,
			type TEXT NOT NULL,
			public_key TEXT,
			private_key_enc TEXT,
			preshared_key_enc TEXT,
			enabled INTEGER DEFAULT 1
		);
		CREATE TABLE settings (
			key TEXT PRIMARY KEY,
			value TEXT,
			encrypted INTEGER DEFAULT 0,
			updated_at DATETIME
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func mustEnc(t *testing.T, s string) string {
	t.Helper()
	e, err := helper.Encrypt(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestExportImportRoundTrip(t *testing.T) {
	db := testDB(t)
	// A peer with an encrypted private key, and one plain + one encrypted setting.
	if _, err := db.Exec(`INSERT INTO vpn_clients (id, name, ip, type, public_key, private_key_enc, enabled) VALUES (1,'laptop','10.0.0.2','wireguard','PUB', ?, 1)`,
		mustEnc(t, "PRIVATE-KEY-MATERIAL")); err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO settings (key,value,encrypted) VALUES ('headscale_url','https://hs.example',0)`)
	db.Exec(`INSERT INTO settings (key,value,encrypted) VALUES ('api_key', ?, 1)`, mustEnc(t, "SECRET-API-KEY"))

	blob, err := Export(db, "correct horse battery", "test", false, false)
	if err != nil {
		t.Fatal(err)
	}

	// The sealed file must not leak plaintext secrets.
	if s := string(blob); strings.Contains(s, "PRIVATE-KEY-MATERIAL") || strings.Contains(s, "SECRET-API-KEY") {
		t.Fatal("plaintext secret leaked into sealed backup file")
	}

	// Mutate the DB so import has something to replace: change the peer, add a stray.
	db.Exec(`UPDATE vpn_clients SET name='changed' WHERE id=1`)
	db.Exec(`INSERT INTO vpn_clients (id,name,ip,type) VALUES (2,'stray','10.0.0.9','wireguard')`)
	db.Exec(`DELETE FROM settings WHERE key='headscale_url'`)

	_, doc, err := Open(blob, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if err := Import(db, doc); err != nil {
		t.Fatal(err)
	}

	// Faithful replace: peer 1 restored, stray peer 2 gone.
	var name string
	if err := db.QueryRow(`SELECT name FROM vpn_clients WHERE id=1`).Scan(&name); err != nil || name != "laptop" {
		t.Fatalf("peer not restored: name=%q err=%v", name, err)
	}
	var strays int
	db.QueryRow(`SELECT COUNT(*) FROM vpn_clients WHERE id=2`).Scan(&strays)
	if strays != 0 {
		t.Fatal("replace did not drop the stray peer")
	}

	// Secret re-encrypted under this host's key and decryptable back to plaintext.
	var enc string
	db.QueryRow(`SELECT private_key_enc FROM vpn_clients WHERE id=1`).Scan(&enc)
	if enc == "" || enc == "PRIVATE-KEY-MATERIAL" {
		t.Fatalf("private key not re-encrypted: %q", enc)
	}
	if dec, err := helper.Decrypt(enc); err != nil || dec != "PRIVATE-KEY-MATERIAL" {
		t.Fatalf("re-encrypted key does not round-trip: dec=%q err=%v", dec, err)
	}

	// Encrypted setting restored + decryptable; plain setting restored as-is.
	var apiEnc string
	var apiFlag int
	db.QueryRow(`SELECT value, encrypted FROM settings WHERE key='api_key'`).Scan(&apiEnc, &apiFlag)
	if apiFlag != 1 {
		t.Fatal("encrypted flag not preserved on setting")
	}
	if dec, err := helper.Decrypt(apiEnc); err != nil || dec != "SECRET-API-KEY" {
		t.Fatalf("encrypted setting not restored: dec=%q err=%v", dec, err)
	}
	var hsURL string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='headscale_url'`).Scan(&hsURL); err != nil || hsURL != "https://hs.example" {
		t.Fatalf("plain setting not restored: %q err=%v", hsURL, err)
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	db := testDB(t)
	db.Exec(`INSERT INTO settings (key,value,encrypted) VALUES ('x','y',0)`)
	blob, err := Export(db, "the right passphrase", "test", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(blob, "the WRONG passphrase"); err != errBadPass {
		t.Fatalf("expected errBadPass, got %v", err)
	}
}

func TestOpenTamperedHeader(t *testing.T) {
	db := testDB(t)
	db.Exec(`INSERT INTO settings (key,value,encrypted) VALUES ('x','y',0)`)
	blob, _ := Export(db, "the right passphrase", "test", false, false)
	// Flip a cleartext-header VALUE (panel_version test→prod). It's bound as GCM AAD,
	// so the open must reject it. (Tampering a KEY wouldn't test this — Go's JSON
	// unmarshal matches struct tags case-insensitively.)
	tampered := strings.Replace(string(blob), `"panel_version": "test"`, `"panel_version": "prod"`, 1)
	if tampered == string(blob) {
		t.Fatal("test setup: panel_version not found to tamper")
	}
	if _, _, err := Open([]byte(tampered), "the right passphrase"); err == nil {
		t.Fatal("tampered header accepted")
	}
}

func TestOpenTamperedKDFParams(t *testing.T) {
	db := testDB(t)
	db.Exec(`INSERT INTO settings (key,value,encrypted) VALUES ('x','y',0)`)
	blob, _ := Export(db, "the right passphrase", "test", false, false)
	// Downgrade the iteration count in the cleartext envelope. It's now bound as AAD,
	// so the open must reject it (defends a future iter-downgrade attack).
	tampered := strings.Replace(string(blob), `"iter": 600000`, `"iter": 1`, 1)
	if tampered == string(blob) {
		t.Fatal("test setup: iter field not found to tamper")
	}
	if _, _, err := Open([]byte(tampered), "the right passphrase"); err == nil {
		t.Fatal("tampered KDF params accepted")
	}
}

func TestSealOpenUnit(t *testing.T) {
	salt, nonce, ct, err := seal("pw", []byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := open("pw", salt, nonce, ct, []byte("aad"))
	if err != nil || string(pt) != "hello" {
		t.Fatalf("round trip failed: %q %v", pt, err)
	}
	if _, err := open("pw", salt, nonce, ct, []byte("different-aad")); err != errBadPass {
		t.Fatal("aad mismatch should fail")
	}
}
