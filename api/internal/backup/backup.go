// Package backup implements the panel's encrypted config export/import
// ("Backup & migrate"). A backup is a single passphrase-sealed file that carries
// the panel's configuration — VPN peers/ACLs, firewall, routing, settings, and
// optionally admin users and the fleet CA/machines — so a whole panel can be
// cloned onto a fresh host. Import is a faithful REPLACE: per included table it
// wipes and reloads rows preserving primary keys (so foreign keys stay intact),
// transactionally, then reconciles the live system (nftables, WireGuard, ACLs).
package backup

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"api/internal/helper"
)

const (
	fileFormat  = "wg-panel-backup"
	fileVersion = 1
	// MinPassphrase is the shortest passphrase we accept — a backup carries every
	// secret the panel holds, so a weak passphrase is a real risk.
	MinPassphrase = 8
)

// Table tiers. Core is always exported; users and fleet are opt-in.
var (
	coreTables = []string{
		"vpn_clients", "vpn_acl_rules", "vpn_router_config", "vpn_virtual_ips", "vpn_virtual_ip_acl",
		"firewall_entries", "jails", "domain_routes", "settings",
	}
	userTables  = []string{"users", "users_notification_preferences"}
	fleetTables = []string{"fleet_ca", "fleet_machines"}
)

// secretCols lists columns encrypted with the host's ENCRYPTION_SECRET: decrypted to
// plaintext on export, re-encrypted under the destination host on import. The
// settings table is handled separately via its per-row `encrypted` flag.
var secretCols = map[string][]string{
	"vpn_clients": {"private_key_enc", "preshared_key_enc"},
	"users":       {"totp_secret_enc"},
	"fleet_ca":    {"key_enc"},
}

// tableLabels are human names for the import preview.
var tableLabels = map[string]string{
	"vpn_clients": "VPN peers", "vpn_acl_rules": "Peer ACL rules", "vpn_router_config": "Router config",
	"vpn_virtual_ips": "Virtual IPs", "vpn_virtual_ip_acl": "Virtual-IP ACLs",
	"firewall_entries": "Firewall entries", "jails": "Jails", "domain_routes": "Domain routes", "settings": "Settings",
	"users": "Admin users", "users_notification_preferences": "Notification prefs",
	"fleet_ca": "Fleet CA", "fleet_machines": "Fleet machines",
}

// allowed is the full whitelist of table names we ever touch. Every table name that
// reaches a SQL string is checked against this set, so no file-supplied name can be
// interpolated blindly.
var allowed = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range append(append(append([]string{}, coreTables...), userTables...), fleetTables...) {
		m[t] = true
	}
	return m
}()

// orderedTables returns every table in a stable order (core, then users, then fleet)
// — used so export and import always process tables the same way.
func orderedTables() []string {
	return append(append(append([]string{}, coreTables...), userTables...), fleetTables...)
}

// Header is the cleartext envelope — identifies a file without the passphrase and is
// bound as GCM additional-authenticated-data so it can't be swapped.
type Header struct {
	Format       string   `json:"format"`
	Version      int      `json:"version"`
	PanelVersion string   `json:"panel_version,omitempty"`
	CreatedAt    string   `json:"created_at"`
	Includes     []string `json:"includes"` // "core" | "users" | "fleet"
}

// envelope is the on-disk file: cleartext header + sealed body.
type envelope struct {
	Header
	KDF   string `json:"kdf"`
	Iter  int    `json:"iter"`
	Salt  string `json:"salt"`  // base64
	Nonce string `json:"nonce"` // base64
	Data  string `json:"data"`  // base64 AES-256-GCM(document json)
}

// Document is the sealed payload: table name -> rows.
type Document struct {
	Tables map[string][]map[string]any `json:"tables"`
}

// Export gathers the requested tiers into a passphrase-sealed backup file.
func Export(db *sql.DB, passphrase, panelVersion string, includeUsers, includeFleet bool) ([]byte, error) {
	includes := []string{"core"}
	tables := append([]string{}, coreTables...)
	if includeUsers {
		tables = append(tables, userTables...)
		includes = append(includes, "users")
	}
	if includeFleet {
		tables = append(tables, fleetTables...)
		includes = append(includes, "fleet")
	}

	doc := Document{Tables: map[string][]map[string]any{}}
	for _, t := range tables {
		rows, err := dumpTable(db, t)
		if err != nil {
			return nil, fmt.Errorf("export %s: %w", t, err)
		}
		doc.Tables[t] = rows
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	hdr := Header{
		Format: fileFormat, Version: fileVersion, PanelVersion: panelVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Includes: includes,
	}
	aad, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	salt, nonce, ct, err := seal(passphrase, body, aad)
	if err != nil {
		return nil, err
	}
	env := envelope{
		Header: hdr, KDF: kdfName, Iter: kdfIter,
		Salt: b64(salt), Nonce: b64(nonce), Data: b64(ct),
	}
	return json.MarshalIndent(env, "", "  ")
}

// Open validates and decrypts a backup file, returning its header and document.
func Open(raw []byte, passphrase string) (Header, *Document, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Header{}, nil, fmt.Errorf("not a valid backup file")
	}
	if env.Format != fileFormat {
		return Header{}, nil, fmt.Errorf("not a %s file", fileFormat)
	}
	if env.Version != fileVersion {
		return Header{}, nil, fmt.Errorf("unsupported backup version %d (this panel reads v%d)", env.Version, fileVersion)
	}
	salt, err1 := b64d(env.Salt)
	nonce, err2 := b64d(env.Nonce)
	ct, err3 := b64d(env.Data)
	if err1 != nil || err2 != nil || err3 != nil {
		return Header{}, nil, fmt.Errorf("corrupt backup file")
	}
	aad, err := json.Marshal(env.Header)
	if err != nil {
		return Header{}, nil, err
	}
	body, err := open(passphrase, salt, nonce, ct, aad)
	if err != nil {
		return Header{}, nil, err // errBadPass
	}
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep integers exact for id/foreign-key columns
	if err := dec.Decode(&doc); err != nil {
		return Header{}, nil, fmt.Errorf("corrupt backup contents")
	}
	return env.Header, &doc, nil
}

// TablePlan is one line of the import preview.
type TablePlan struct {
	Table    string `json:"table"`
	Label    string `json:"label"`
	Existing int    `json:"existing"` // rows currently on this host (replaced)
	Incoming int    `json:"incoming"` // rows in the backup
	Missing  bool   `json:"missing"`  // table absent here (service disabled) → skipped
}

// Plan describes what an import would do, without changing anything.
func Plan(db *sql.DB, doc *Document) []TablePlan {
	var out []TablePlan
	for _, t := range orderedTables() {
		rows, ok := doc.Tables[t]
		if !ok {
			continue
		}
		tp := TablePlan{Table: t, Label: tableLabels[t], Incoming: len(rows)}
		if !tableExists(db, t) {
			tp.Missing = true
		} else {
			tp.Existing = countRows(db, t)
		}
		out = append(out, tp)
	}
	return out
}

// Import applies a document as a faithful replace, transactionally. Foreign-key
// checks are deferred to commit so tables can be wiped/reloaded in any order.
func Import(db *sql.DB, doc *Document) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("PRAGMA defer_foreign_keys=ON"); err != nil {
		return err
	}
	for _, t := range orderedTables() {
		rows, ok := doc.Tables[t]
		if !ok {
			continue
		}
		if !txTableExists(tx, t) {
			continue // service disabled on this host — skip its tables
		}
		if err := restoreTable(tx, t, rows); err != nil {
			return fmt.Errorf("import %s: %w", t, err)
		}
	}
	return tx.Commit()
}

// dumpTable reads a whole table into rows, decrypting secret columns to plaintext.
func dumpTable(db *sql.DB, table string) ([]map[string]any, error) {
	if !allowed[table] {
		return nil, fmt.Errorf("table not allowed: %s", table)
	}
	if !tableExists(db, table) {
		return []map[string]any{}, nil // service not enabled here — nothing to export
	}
	rows, err := db.Query("SELECT * FROM " + table) // table is from our whitelist
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			m[c] = v
		}
		if err := decryptSecrets(table, m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// restoreTable wipes a table and reloads the backup's rows, re-encrypting secrets and
// preserving primary keys. Only columns that exist on this host are written.
func restoreTable(tx *sql.Tx, table string, rows []map[string]any) error {
	if !allowed[table] {
		return fmt.Errorf("table not allowed: %s", table)
	}
	real := txColumns(tx, table)
	if _, err := tx.Exec("DELETE FROM " + table); err != nil {
		return err
	}
	for _, row := range rows {
		encryptSecrets(table, row)
		var cols []string
		var ph []string
		var args []any
		for c, v := range row {
			if !real[c] {
				continue // schema drift: column gone on this host — drop it
			}
			cols = append(cols, `"`+c+`"`)
			ph = append(ph, "?")
			args = append(args, bindValue(v))
		}
		if len(cols) == 0 {
			continue
		}
		q := "INSERT INTO " + table + " (" + strings.Join(cols, ",") + ") VALUES (" + strings.Join(ph, ",") + ")"
		if _, err := tx.Exec(q, args...); err != nil {
			return err
		}
	}
	return nil
}

// decryptSecrets turns a row's ciphertext secret fields into plaintext for export.
func decryptSecrets(table string, m map[string]any) error {
	for _, sc := range secretCols[table] {
		s, ok := m[sc].(string)
		if !ok || s == "" {
			continue
		}
		dec, err := helper.Decrypt(s)
		if err != nil {
			return fmt.Errorf("decrypt %s.%s: %w", table, sc, err)
		}
		m[sc] = dec
	}
	if table == "settings" && truthy(m["encrypted"]) {
		if s, ok := m["value"].(string); ok && s != "" {
			dec, err := helper.Decrypt(s)
			if err != nil {
				return fmt.Errorf("decrypt setting %v: %w", m["key"], err)
			}
			m["value"] = dec
		}
	}
	return nil
}

// encryptSecrets re-seals a row's plaintext secret fields under this host's key for import.
func encryptSecrets(table string, m map[string]any) {
	for _, sc := range secretCols[table] {
		s, ok := m[sc].(string)
		if !ok || s == "" {
			continue
		}
		if enc, err := helper.Encrypt(s); err == nil {
			m[sc] = enc
		}
	}
	if table == "settings" && truthy(m["encrypted"]) {
		if s, ok := m["value"].(string); ok && s != "" {
			if enc, err := helper.Encrypt(s); err == nil {
				m["value"] = enc
			}
		}
	}
}

// bindValue coerces a JSON-decoded value into something the sqlite driver stores with
// the right type. json.Number is split into int64/float64 so integer columns (ids,
// foreign keys) don't degrade to REAL or TEXT.
func bindValue(v any) any {
	n, ok := v.(json.Number)
	if !ok {
		return v
	}
	if strings.ContainsAny(n.String(), ".eE") {
		if f, err := n.Float64(); err == nil {
			return f
		}
	}
	if i, err := n.Int64(); err == nil {
		return i
	}
	return n.String()
}

// truthy reads a JSON/SQL boolean-ish value (1, true, "1", int64) as a flag.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case json.Number:
		return t.String() != "0" && t.String() != ""
	case int64:
		return t != 0
	case float64:
		return t != 0
	case string:
		return t == "1" || t == "true"
	}
	return false
}

func tableExists(db *sql.DB, table string) bool {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
	return err == nil && n > 0
}

func countRows(db *sql.DB, table string) int {
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		return 0
	}
	return n
}

func txTableExists(tx *sql.Tx, table string) bool {
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
	return err == nil && n > 0
}

// txColumns returns the set of real column names for a table on this host.
func txColumns(tx *sql.Tx, table string) map[string]bool {
	set := map[string]bool{}
	rows, err := tx.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return set
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			set[name] = true
		}
	}
	return set
}

func b64(b []byte) string           { return base64.StdEncoding.EncodeToString(b) }
func b64d(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
