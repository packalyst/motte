package dhcp

import (
	"testing"

	"api/internal/database"
)

// TestNetworkPolicyFromDB checks which devices the firewall policy picks up from the database:
// only approved, unblocked devices inside the subnet are forwardable, each with its own grants;
// blocked ones are listed by MAC; new devices take the network's internet default; and grants
// disappear with the VPN client they name.
func TestNetworkPolicyFromDB(t *testing.T) {
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DELETE FROM dhcp_client_acl`, `DELETE FROM dhcp_clients`, `DELETE FROM dhcp_networks`, `DELETE FROM vpn_clients`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{db: db}
	n := &Network{Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", PoolStart: "10.20.20.50",
		PoolEnd: "10.20.20.200", LeaseSecs: 3600, Mode: "approve", NATEnabled: true, Enabled: true}
	if n.ID, err = s.createNetwork(n); err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec(`INSERT INTO vpn_clients (name, ip, type) VALUES ('laptop', '10.8.0.2', 'wireguard')`)
	if err != nil {
		t.Fatal(err)
	}
	vpnID, _ := res.LastInsertId()

	// Devices as DHCP sees them: the network's internet default (on) seeds every new one.
	for _, d := range []struct{ mac, ip string }{
		{"02:00:00:00:00:01", "10.20.20.51"}, // camera: approved + granted
		{"02:00:00:00:00:02", "10.20.20.52"}, // pending
		{"02:00:00:00:00:03", "10.20.20.53"}, // blocked
		{"02:00:00:00:00:04", "10.99.0.4"},   // approved but outside the subnet
	} {
		if err := s.upsertClient(n.ID, d.mac, d.ip, "", false); err != nil {
			t.Fatal(err)
		}
	}
	id := func(mac string) int64 {
		var v int64
		if err := db.QueryRow(`SELECT id FROM dhcp_clients WHERE mac = ?`, mac).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	cam, blocked, outside := id("02:00:00:00:00:01"), id("02:00:00:00:00:03"), id("02:00:00:00:00:04")
	if c, _ := s.getClient(cam); !c.Internet {
		t.Fatal("a new device must take its network's internet default")
	}
	_ = s.setClientApproved(cam, true)
	_ = s.setClientApproved(outside, true)
	_ = s.setClientBlocked(blocked, true, false)
	if ok, _ := s.setDeviceACL(cam, vpnID, false); ok {
		t.Fatal("a grant must wait for the device's VPN access")
	}
	if _, err := db.Exec(`UPDATE dhcp_clients SET vpn_ip = '10.8.128.1' WHERE id = ?`, cam); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.setDeviceACL(cam, vpnID, false); !ok || err != nil {
		t.Fatalf("grant with VPN access on: %v %v", ok, err)
	}

	p, err := s.networkPolicy(n)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Devices) != 1 || p.Devices[0].IP != "10.20.20.51" || p.Devices[0].MAC != "02:00:00:00:00:01" || len(p.Devices[0].Allowed) != 1 || p.Devices[0].Allowed[0].IP != "10.8.0.2" || !p.Devices[0].Internet {
		t.Fatalf("only the approved camera, with its one grant, may be forwardable: %+v", p.Devices)
	}
	if len(p.Blocked) != 1 || p.Blocked[0] != "02:00:00:00:00:03" {
		t.Fatalf("blocked MAC missing: %+v", p.Blocked)
	}

	// Blocking also revokes approval, so an unblocked device in approve mode waits again.
	if c, _ := s.getClient(blocked); c.Approved {
		t.Fatal("a blocked device must not stay approved")
	}

	// Deleting the VPN client removes its grants (foreign key cascade).
	if _, err := db.Exec(`DELETE FROM vpn_clients WHERE id = ?`, vpnID); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.listDeviceACL(cam); len(ids) != 0 {
		t.Fatalf("grants must go with their VPN client, got %v", ids)
	}
}
