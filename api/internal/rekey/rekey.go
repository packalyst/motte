// Package rekey re-encrypts every at-rest secret in the database under a new
// ENCRYPTION_SECRET. It runs as a one-shot (`api --rekey`) with the api stopped,
// so nothing writes to the DB while it runs.
//
// Safety model:
//   - Pre-flight: decrypt EVERY secret with the OLD key first. Abort on any
//     failure of a critical value — better to change nothing than to swap the
//     key and leave rows that can never be decrypted again.
//   - Re-encrypt inside ONE transaction: every row is updated, or none is.
//   - The orchestrator only swaps the key after this exits 0, then verifies with
//     Check (decrypt-all under the new key).
package rekey

import (
	"database/sql"
	"fmt"

	"api/internal/helper"
)

// encCol is one encrypted column to re-key. critical=false means a decrypt
// failure is skipped instead of aborting — used only for the ephemeral,
// write-only vpn_router_config.authkey_enc, which is never read at runtime.
type encCol struct {
	table    string
	column   string
	critical bool
}

// columns is the COMPLETE set of encrypted columns — deliberately including
// users_push_subscriptions, which the backup package's list omits. Settings
// rows (encrypted=1) are handled separately. Table/column names here are fixed
// literals, never user input, so building SQL with them is safe.
var columns = []encCol{
	{"vpn_clients", "private_key_enc", true},
	{"vpn_clients", "preshared_key_enc", true},
	{"users", "totp_secret_enc", true},
	{"fleet_ca", "key_enc", true},
	{"users_push_subscriptions", "key_p256dh", true},
	{"users_push_subscriptions", "key_auth", true},
	{"vpn_router_config", "authkey_enc", false}, // ephemeral, write-only
}

// item is one decrypted secret awaiting re-encryption.
type item struct {
	table  string // "" => a settings row
	column string
	rowid  int64
	setKey string // settings key when table == ""
	plain  string
}

// Report summarizes a scan/run for display.
type Report struct {
	ByCategory map[string]int
	Total      int
	Skipped    int // non-critical values that failed to decrypt
}

func tableExists(db *sql.DB, name string) bool {
	var n string
	return db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n) == nil
}

// scan decrypts every secret with key and returns the plaintexts. A decrypt
// failure of a critical value returns an error so the caller aborts before
// anything is written.
func scan(db *sql.DB, key []byte) ([]item, Report, error) {
	rep := Report{ByCategory: map[string]int{}}
	var items []item

	for _, c := range columns {
		if !tableExists(db, c.table) {
			continue
		}
		q := fmt.Sprintf(`SELECT rowid, %s FROM %s WHERE %s IS NOT NULL AND %s != ''`,
			c.column, c.table, c.column, c.column)
		rows, err := db.Query(q)
		if err != nil {
			return nil, rep, fmt.Errorf("scan %s.%s: %w", c.table, c.column, err)
		}
		for rows.Next() {
			var rowid int64
			var enc string
			if err := rows.Scan(&rowid, &enc); err != nil {
				rows.Close()
				return nil, rep, err
			}
			plain, err := helper.DecryptWith(key, enc)
			if err != nil {
				if c.critical {
					rows.Close()
					return nil, rep, fmt.Errorf("decrypt %s.%s (rowid %d) failed with the current key: %w", c.table, c.column, rowid, err)
				}
				rep.Skipped++
				continue
			}
			items = append(items, item{table: c.table, column: c.column, rowid: rowid, plain: plain})
			rep.ByCategory[c.table]++
			rep.Total++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, rep, err
		}
		rows.Close()
	}

	if tableExists(db, "settings") {
		rows, err := db.Query(`SELECT key, value FROM settings WHERE encrypted=1 AND value IS NOT NULL AND value != ''`)
		if err != nil {
			return nil, rep, fmt.Errorf("scan settings: %w", err)
		}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				rows.Close()
				return nil, rep, err
			}
			plain, err := helper.DecryptWith(key, v)
			if err != nil {
				rows.Close()
				return nil, rep, fmt.Errorf("decrypt settings[%s] failed with the current key: %w", k, err)
			}
			items = append(items, item{setKey: k, plain: plain})
			rep.ByCategory["settings"]++
			rep.Total++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, rep, err
		}
		rows.Close()
	}

	return items, rep, nil
}

// Run performs the full re-key: pre-flight decrypt-all with oldKey, then
// re-encrypt every value with newKey inside a single transaction. On any error
// the transaction rolls back and the database is left unchanged.
func Run(db *sql.DB, oldKey, newKey []byte) (Report, error) {
	items, rep, err := scan(db, oldKey)
	if err != nil {
		return rep, err
	}

	tx, err := db.Begin()
	if err != nil {
		return rep, err
	}
	for _, it := range items {
		enc, err := helper.EncryptWith(newKey, it.plain)
		if err != nil {
			tx.Rollback()
			return rep, fmt.Errorf("re-encrypt failed: %w", err)
		}
		if it.table == "" {
			_, err = tx.Exec(`UPDATE settings SET value=? WHERE key=?`, enc, it.setKey)
		} else {
			_, err = tx.Exec(fmt.Sprintf(`UPDATE %s SET %s=? WHERE rowid=?`, it.table, it.column), enc, it.rowid)
		}
		if err != nil {
			tx.Rollback()
			return rep, fmt.Errorf("update %s.%s: %w", it.table, it.column, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return rep, err
	}
	return rep, nil
}

// Check decrypts every secret with key (no writes) and returns an error if any
// critical value fails — used to verify the database after the key swap.
func Check(db *sql.DB, key []byte) (Report, error) {
	_, rep, err := scan(db, key)
	return rep, err
}
