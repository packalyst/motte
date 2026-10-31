package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// An install from before LAN VPN addresses gets the new columns and the index that keeps two devices
// off one VPN address; its grants go, as no device has VPN access switched on yet.
func TestMigrationAddsLANVPNAddress(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE dhcp_networks (id INTEGER PRIMARY KEY, nat_enabled INTEGER);
		CREATE TABLE dhcp_clients (id INTEGER PRIMARY KEY, network_id INTEGER, mac TEXT UNIQUE, approved INTEGER);
		CREATE TABLE dhcp_client_acl (id INTEGER PRIMARY KEY, device_id INTEGER, source_client_id INTEGER);
		CREATE TABLE vpn_acl_rules (id INTEGER PRIMARY KEY);
		CREATE TABLE users (id INTEGER PRIMARY KEY);
		INSERT INTO dhcp_clients (id, network_id, mac) VALUES (1, 1, 'a'), (2, 1, 'b');
		INSERT INTO dhcp_client_acl (device_id, source_client_id) VALUES (1, 7)`); err != nil {
		t.Fatal(err)
	}
	runMigrations(db)

	var vpnIP string
	var both int
	if err := db.QueryRow(`SELECT vpn_ip FROM dhcp_clients WHERE id = 1`).Scan(&vpnIP); err != nil || vpnIP != "" {
		t.Fatalf("vpn_ip must exist and start empty: %q %v", vpnIP, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('dhcp_client_acl') WHERE name = 'bidirectional'`).Scan(&both); err != nil || both != 1 {
		t.Fatalf("bidirectional column missing: %v", err)
	}
	var grants int
	if db.QueryRow(`SELECT COUNT(*) FROM dhcp_client_acl`).Scan(&grants); grants != 0 {
		t.Fatalf("grants of devices without VPN access must go, %d left", grants)
	}
	if _, err := db.Exec(`UPDATE dhcp_clients SET vpn_ip = '10.8.128.3'`); err == nil {
		t.Fatal("two devices must not share a VPN address")
	}
	if _, err := db.Exec(`UPDATE dhcp_clients SET vpn_ip = '10.8.128.3' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
}
