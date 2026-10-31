package vpn

import (
	"slices"
	"testing"

	"api/internal/database"
	"api/internal/helper"
)

// A Headscale node granted a LAN device reaches the device's VPN address in the Headscale policy
// (two-way: the address reaches the node too); a node set to block everyone gets no entry.
func TestHeadscalePolicyCarriesLANGrants(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("WG_SERVER_IP", "10.8.0.1")
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, _ := database.GetDB()
	exec := func(q string, args ...any) int64 {
		res, err := db.Exec(q, args...)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	net := exec(`INSERT INTO dhcp_networks (iface, cidr, gateway_ip, pool_start, pool_end) VALUES ('ens19', '10.20.20.0/24', '10.20.20.1', '10.20.20.50', '10.20.20.200')`)
	cam := exec(`INSERT INTO dhcp_clients (network_id, mac, ip, approved, vpn_ip) VALUES (?, '02:00:00:00:00:01', '10.20.20.51', 1, '10.8.128.3')`, net)
	nas := exec(`INSERT INTO dhcp_clients (network_id, mac, ip, approved, vpn_ip) VALUES (?, '02:00:00:00:00:02', '10.20.20.52', 1, '10.8.128.4')`, net)
	phone := exec(`INSERT INTO vpn_clients (name, ip, type) VALUES ('phone', '100.64.0.3', 'headscale')`)
	laptop := exec(`INSERT INTO vpn_clients (name, ip, type) VALUES ('laptop', '100.64.0.4', 'headscale')`)
	shut := exec(`INSERT INTO vpn_clients (name, ip, type, acl_policy) VALUES ('shut', '100.64.0.5', 'headscale', ?)`, helper.ACLPolicyBlockAll)
	exec(`INSERT INTO dhcp_client_acl (device_id, source_client_id, bidirectional) VALUES (?, ?, 0), (?, ?, 1), (?, ?, 1)`,
		cam, phone, nas, laptop, cam, shut)

	acl, err := generateHeadscaleACL()
	if err != nil {
		t.Fatal(err)
	}
	has := func(src, dst string) bool {
		return slices.ContainsFunc(acl.ACLs, func(e ACLEntry) bool {
			return slices.Equal(e.Src, []string{src}) && slices.Equal(e.Dst, []string{dst})
		})
	}
	for _, c := range []struct {
		src, dst string
		want     bool
	}{
		{"phone", "10.8.128.3:*", true},  // one-way grant
		{"10.8.128.3", "phone:*", false}, // ... and nothing back
		{"laptop", "10.8.128.4:*", true}, // two-way grant
		{"10.8.128.4", "laptop:*", true}, // ... both ways
		{"shut", "10.8.128.3:*", false},  // blocks everyone: no entry
		{"10.8.128.3", "shut:*", false},
	} {
		if has(c.src, c.dst) != c.want {
			t.Errorf("%s → %s: present=%v, want %v (%+v)", c.src, c.dst, !c.want, c.want, acl.ACLs)
		}
	}
}
