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

	blob, err := Export(db, "correct horse battery", "test", false, false, "")
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
	blob, err := Export(db, "the right passphrase", "test", false, false, "")
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
	blob, _ := Export(db, "the right passphrase", "test", false, false, "")
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
	blob, _ := Export(db, "the right passphrase", "test", false, false, "")
	// Downgrade the iteration count in the cleartext envelope. It's now bound as AAD,
	// so the open must reject it (defends a future iter-downgrade attack).
	tampered := strings.Replace(string(blob), `"iter": 3`, `"iter": 1`, 1)
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

// A machine's last report is a cache its agent resends: a backup leaves it out (it can be megabytes),
// and an import restores the machine without it.
func TestExportLeavesOutMachineReport(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`CREATE TABLE fleet_machines (id TEXT PRIMARY KEY, name TEXT, last_report TEXT)`); err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO fleet_machines (id, name, last_report) VALUES ('m1', 'web-01', '{"cves":"BIG-REPORT"}')`)

	blob, err := Export(db, "correct horse battery", "test", false, true, "")
	if err != nil {
		t.Fatal(err)
	}
	_, doc, err := Open(blob, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	rows := doc.Tables["fleet_machines"]
	if len(rows) != 1 || rows[0]["name"] != "web-01" {
		t.Fatalf("machine not exported: %+v", rows)
	}
	if _, ok := rows[0]["last_report"]; ok {
		t.Fatal("last_report exported")
	}
	if err := Import(db, doc); err != nil {
		t.Fatal(err)
	}
	var name string
	var report sql.NullString
	if err := db.QueryRow(`SELECT name, last_report FROM fleet_machines WHERE id='m1'`).Scan(&name, &report); err != nil || name != "web-01" || report.Valid {
		t.Fatalf("machine not restored without its report: name=%q report=%v err=%v", name, report, err)
	}
}

// A user's webhook URL travels decrypted inside the sealed file and is re-encrypted under the
// importing host's key; the WireGuard server key rides along and is handed to the restore hook.
func TestExportImportUserSecretsAndWireGuardKey(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);
		CREATE TABLE notification_channels (user_id INTEGER PRIMARY KEY, webhook_url_enc TEXT NOT NULL DEFAULT '', webhook_enabled INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO users (id, username) VALUES (1, 'owner')`)
	if _, err := db.Exec(`INSERT INTO notification_channels (user_id, webhook_url_enc, webhook_enabled) VALUES (1, ?, 1)`,
		mustEnc(t, "https://hooks.example.test/SECRET-TOKEN")); err != nil {
		t.Fatal(err)
	}
	const wgKey = "WG-PRIVATE-KEY-MATERIAL"

	blob, err := Export(db, "correct horse battery", "test", true, false, wgKey)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(blob); strings.Contains(s, "SECRET-TOKEN") || strings.Contains(s, wgKey) {
		t.Fatal("secret visible in the sealed file")
	}
	_, doc, err := Open(blob, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if doc.WireGuardKey != wgKey {
		t.Fatalf("WireGuard key = %q", doc.WireGuardKey)
	}
	if last := Plan(db, doc); last[len(last)-1].Table != "wireguard_key" {
		t.Fatalf("preview doesn't list the WireGuard key: %+v", last)
	}

	db.Exec(`DELETE FROM notification_channels`)
	var restored string
	svc := New(Deps{DB: func() *sql.DB { return db }, RestoreWireGuardKey: func(k string) error { restored = k; return nil }})
	if _, err := svc.apply(doc); err != nil {
		t.Fatal(err)
	}
	if restored != wgKey {
		t.Fatalf("restore hook got %q", restored)
	}
	var enc string
	if err := db.QueryRow(`SELECT webhook_url_enc FROM notification_channels WHERE user_id=1`).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if dec, err := helper.Decrypt(enc); err != nil || dec != "https://hooks.example.test/SECRET-TOKEN" {
		t.Fatalf("webhook not re-encrypted: enc=%q dec=%q err=%v", enc, dec, err)
	}
}

func TestOpenRejectsOldFormat(t *testing.T) {
	db := testDB(t)
	blob, err := Export(db, "correct horse battery", "test", false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(string(blob), `"motte-backup"`, `"wg-panel-backup"`, 1)
	if _, _, err := Open([]byte(old), "correct horse battery"); err == nil {
		t.Fatal("a wg-panel-backup file opened")
	}
}

// Restoring a backup whose fleet CA was replaced since warns that moved machines will need
// re-enrolling; the same CA, or no fleet tier, doesn't.
func TestFleetCAWarning(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS fleet_ca (id INTEGER PRIMARY KEY, cert_pem TEXT NOT NULL, key_enc TEXT NOT NULL, created_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(`INSERT INTO fleet_ca (cert_pem, key_enc, created_at) VALUES ('CURRENT-CA', 'k', 'now')`)
	doc := func(pem string) *Document {
		return &Document{Tables: map[string][]map[string]any{"fleet_ca": {{"cert_pem": pem}}}}
	}
	if w := fleetCAWarning(db, doc("CURRENT-CA\n")); len(w) != 0 {
		t.Errorf("same CA warned: %v", w)
	}
	if w := fleetCAWarning(db, doc("REPLACED-CA")); len(w) != 1 {
		t.Error("a replaced CA didn't warn")
	}
	if w := fleetCAWarning(db, &Document{Tables: map[string][]map[string]any{}}); len(w) != 0 {
		t.Error("warned without a fleet tier")
	}
}

// A restore keeps the domain routes to LAN devices: reloading the devices wipes them first, and
// that wipe cascades into the routes, so the routes must be restored after the devices.
func TestImportKeepsLANDeviceRoutes(t *testing.T) {
	t.Setenv("ENCRYPTION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	helper.InitEncryption()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db")+"?_foreign_keys=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE dhcp_networks (id INTEGER PRIMARY KEY, iface TEXT);
		CREATE TABLE dhcp_clients (id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL, mac TEXT,
			FOREIGN KEY (network_id) REFERENCES dhcp_networks(id) ON DELETE CASCADE);
		CREATE TABLE domain_routes (id INTEGER PRIMARY KEY, domain TEXT, target_ip TEXT, target_port INTEGER,
			lan_device_id INTEGER REFERENCES dhcp_clients(id) ON DELETE CASCADE);
		INSERT INTO dhcp_networks VALUES (1, 'ens19');
		INSERT INTO dhcp_clients VALUES (1, 1, '02:00:00:00:00:01');
		INSERT INTO domain_routes VALUES (1, 'cam.example.test', '10.8.128.1', 80, 1);
	`); err != nil {
		t.Fatal(err)
	}
	blob, err := Export(db, "correct horse battery", "test", false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	_, doc, err := Open(blob, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if err := Import(db, doc); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM domain_routes WHERE lan_device_id = 1`).Scan(&n)
	if n != 1 {
		t.Fatalf("the route to the LAN device was lost in the restore: %d left", n)
	}
}
