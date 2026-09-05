package rekey

import (
	"database/sql"
	"path/filepath"
	"testing"

	"api/internal/helper"

	_ "github.com/mattn/go-sqlite3"
)

var (
	keyA = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	keyB = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`CREATE TABLE vpn_clients (id INTEGER PRIMARY KEY, private_key_enc TEXT, preshared_key_enc TEXT)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY, totp_secret_enc TEXT)`,
		`CREATE TABLE fleet_ca (id INTEGER PRIMARY KEY, key_enc TEXT)`,
		`CREATE TABLE users_push_subscriptions (id INTEGER PRIMARY KEY, key_p256dh TEXT, key_auth TEXT)`,
		`CREATE TABLE vpn_router_config (id INTEGER PRIMARY KEY, authkey_enc TEXT)`,
		`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, encrypted INTEGER DEFAULT 0)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func enc(t *testing.T, keyHex, pt string) string {
	t.Helper()
	k, _ := helper.ParseKey(keyHex)
	c, err := helper.EncryptWith(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRekeyRoundTrip(t *testing.T) {
	oldKey, _ := helper.ParseKey(keyA)
	newKey, _ := helper.ParseKey(keyB)
	db := openTestDB(t)
	defer db.Close()

	db.Exec(`INSERT INTO vpn_clients (private_key_enc, preshared_key_enc) VALUES (?,?)`, enc(t, keyA, "wg-priv"), enc(t, keyA, "wg-psk"))
	db.Exec(`INSERT INTO vpn_clients (private_key_enc, preshared_key_enc) VALUES (?,?)`, enc(t, keyA, "wg-priv2"), "") // empty psk skipped
	db.Exec(`INSERT INTO users (totp_secret_enc) VALUES (?)`, enc(t, keyA, "totp"))
	db.Exec(`INSERT INTO fleet_ca (id,key_enc) VALUES (1,?)`, enc(t, keyA, "ca-key"))
	db.Exec(`INSERT INTO users_push_subscriptions (key_p256dh,key_auth) VALUES (?,?)`, enc(t, keyA, "p256"), enc(t, keyA, "auth"))
	db.Exec(`INSERT INTO vpn_router_config (id,authkey_enc) VALUES (1,?)`, enc(t, keyA, "authkey"))
	db.Exec(`INSERT INTO settings (key,value,encrypted) VALUES ('adguard_password',?,1)`, enc(t, keyA, "adg-pass"))
	db.Exec(`INSERT INTO settings (key,value,encrypted) VALUES ('display_timezone','UTC',0)`) // plaintext, untouched

	rep, err := Run(db, oldKey, newKey)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Total != 9 {
		t.Errorf("expected 9 re-keyed secrets, got %d (%v)", rep.Total, rep.ByCategory)
	}

	check := func(q, want string) {
		var e string
		if err := db.QueryRow(q).Scan(&e); err != nil {
			t.Fatal(err)
		}
		got, err := helper.DecryptWith(newKey, e)
		if err != nil || got != want {
			t.Errorf("newKey decrypt %q: got %q err %v", want, got, err)
		}
		if _, err := helper.DecryptWith(oldKey, e); err == nil {
			t.Errorf("oldKey should no longer decrypt %q", want)
		}
	}
	check(`SELECT private_key_enc FROM vpn_clients WHERE id=1`, "wg-priv")
	check(`SELECT preshared_key_enc FROM vpn_clients WHERE id=1`, "wg-psk")
	check(`SELECT private_key_enc FROM vpn_clients WHERE id=2`, "wg-priv2")
	check(`SELECT totp_secret_enc FROM users WHERE id=1`, "totp")
	check(`SELECT key_enc FROM fleet_ca WHERE id=1`, "ca-key")
	check(`SELECT key_p256dh FROM users_push_subscriptions WHERE id=1`, "p256") // the gap this closes
	check(`SELECT key_auth FROM users_push_subscriptions WHERE id=1`, "auth")
	check(`SELECT authkey_enc FROM vpn_router_config WHERE id=1`, "authkey")
	check(`SELECT value FROM settings WHERE key='adguard_password'`, "adg-pass")

	var tz string
	db.QueryRow(`SELECT value FROM settings WHERE key='display_timezone'`).Scan(&tz)
	if tz != "UTC" {
		t.Errorf("plaintext (encrypted=0) setting changed: %q", tz)
	}

	if _, err := Check(db, newKey); err != nil {
		t.Errorf("Check(newKey) should pass: %v", err)
	}
	if _, err := Check(db, oldKey); err == nil {
		t.Errorf("Check(oldKey) should fail after rotation")
	}
}

func TestRekeyPreflightAbortLeavesDataIntact(t *testing.T) {
	oldKey, _ := helper.ParseKey(keyA)
	newKey, _ := helper.ParseKey(keyB)
	db := openTestDB(t)
	defer db.Close()

	// A critical value that won't decrypt with oldKey, plus a good one.
	db.Exec(`INSERT INTO users (totp_secret_enc) VALUES ('not-valid-ciphertext')`)
	db.Exec(`INSERT INTO fleet_ca (id,key_enc) VALUES (1,?)`, enc(t, keyA, "ca-key"))

	if _, err := Run(db, oldKey, newKey); err == nil {
		t.Fatal("expected preflight abort on an undecryptable critical value")
	}
	// Nothing was written: the good row still decrypts with the OLD key.
	var e string
	db.QueryRow(`SELECT key_enc FROM fleet_ca WHERE id=1`).Scan(&e)
	if got, err := helper.DecryptWith(oldKey, e); err != nil || got != "ca-key" {
		t.Errorf("DB must be unchanged after abort; got %q err %v", got, err)
	}
}

func TestRekeyNonCriticalSkip(t *testing.T) {
	oldKey, _ := helper.ParseKey(keyA)
	newKey, _ := helper.ParseKey(keyB)
	db := openTestDB(t)
	defer db.Close()

	db.Exec(`INSERT INTO vpn_router_config (id,authkey_enc) VALUES (1,'garbage-ephemeral')`) // non-critical
	db.Exec(`INSERT INTO users (totp_secret_enc) VALUES (?)`, enc(t, keyA, "totp"))

	rep, err := Run(db, oldKey, newKey)
	if err != nil {
		t.Fatalf("must not abort on a non-critical decrypt failure: %v", err)
	}
	if rep.Skipped != 1 {
		t.Errorf("expected 1 skipped (ephemeral authkey), got %d", rep.Skipped)
	}
	var e string
	db.QueryRow(`SELECT totp_secret_enc FROM users WHERE id=1`).Scan(&e)
	if got, _ := helper.DecryptWith(newKey, e); got != "totp" {
		t.Errorf("totp should be re-keyed to newKey, got %q", got)
	}
}
