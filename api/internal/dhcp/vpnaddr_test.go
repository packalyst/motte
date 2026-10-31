package dhcp

import (
	"strings"
	"testing"

	"api/internal/database"
)

// A granted device is reachable at its VPN address: what arrives there over a VPN interface is
// swapped to the device, and only a two-way grant lets the device reach into the VPN (from its
// VPN address, so the reply finds it). Without a grant or a valid VPN address there is no swap.
func TestReachabilityVPNAddress(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", Mode: "approve", Enabled: true}}
	pol := map[int64]netPolicy{1: {Devices: []devicePolicy{
		{IP: "10.20.20.51", MAC: "02:00:00:00:00:51", VPNIP: "10.8.128.1", Allowed: []vpnGrant{{IP: "10.8.0.2"}}},               // one-way
		{IP: "10.20.20.52", MAC: "02:00:00:00:00:52", VPNIP: "10.8.128.2", Allowed: []vpnGrant{{IP: "100.64.0.3", Both: true}}}, // two-way
		{IP: "10.20.20.53", MAC: "02:00:00:00:00:53", VPNIP: "10.8.128.3"},                                                      // nobody
		{IP: "10.20.20.54", MAC: "02:00:00:00:00:54", Allowed: []vpnGrant{{IP: "10.8.0.2"}}},                                    // no VPN address
	}}}
	got := renderReachability(nets, pol, "eth0", testPrivateRanges)
	for _, want := range []string{
		`ip saddr 10.8.0.2 ip daddr 10.20.20.51 accept`,
		`iifname { "wg0", "tailscale0" } ip daddr 10.8.128.1 dnat ip to 10.20.20.51`,
		`ip saddr 100.64.0.3 ip daddr 10.20.20.52 accept`,
		`iifname "ens19" ether saddr 02:00:00:00:00:52 ip saddr 10.20.20.52 ip daddr 100.64.0.3 accept`,
		`iifname { "wg0", "tailscale0" } ip daddr 10.8.128.2 dnat ip to 10.20.20.52`,
		`iifname "ens19" ip saddr 10.20.20.52 oifname { "wg0", "tailscale0" } snat ip to 10.8.128.2`,
		`ip saddr 10.8.0.2 ip daddr 10.20.20.54 accept`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{
		`ip saddr 10.20.20.51 ip daddr 10.8.0.2 accept`, // one-way: the device can't reach in
		`snat ip to 10.8.128.1`,                         // ... nor leave from its VPN address
		`10.8.128.3`,                                    // nobody granted: no swap at all
		`dnat ip to 10.20.20.54`,                        // no VPN address: nothing to swap
	} {
		if strings.Contains(got, bad) {
			t.Fatalf("must not contain %q:\n%s", bad, got)
		}
	}
	// Every swap is scoped to the VPN interfaces: the VPN address never answers from the WAN or LAN.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "dnat") && !strings.Contains(line, `iifname { "wg0", "tailscale0" }`) {
			t.Fatalf("an address swap not scoped to the VPN interfaces: %q", line)
		}
	}
}

// A device gets a VPN address on its first grant: from the upper half of the WireGuard range, past
// every address a VPN client or virtual IP holds, never shared, and kept. The firewall and the
// Headscale policy only use an address held by the device alone.
func TestVPNAddressAssignment(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("WG_SERVER_IP", "10.8.0.1")
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DELETE FROM dhcp_client_acl`, `DELETE FROM dhcp_clients`, `DELETE FROM dhcp_networks`, `DELETE FROM vpn_virtual_ips`, `DELETE FROM vpn_clients`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{db: db}
	n := &Network{Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", PoolStart: "10.20.20.50",
		PoolEnd: "10.20.20.200", LeaseSecs: 3600, Mode: "approve", Enabled: true}
	if n.ID, err = s.createNetwork(n); err != nil {
		t.Fatal(err)
	}
	insert := func(q string, args ...any) int64 {
		res, err := db.Exec(q, args...)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	// The first two upper-half addresses are taken: a virtual IP and a VPN client.
	host := insert(`INSERT INTO vpn_clients (name, ip, type) VALUES ('nas', '10.8.128.2', 'wireguard')`)
	insert(`INSERT INTO vpn_virtual_ips (client_id, ip) VALUES (?, '10.8.128.1')`, host)
	phone := insert(`INSERT INTO vpn_clients (name, ip, type) VALUES ('phone', '100.64.0.3', 'headscale')`)

	for _, mac := range []string{"02:00:00:00:00:01", "02:00:00:00:00:02"} {
		if err := s.upsertClient(n.ID, mac, "10.20.20.5"+mac[len(mac)-1:], "", false); err != nil {
			t.Fatal(err)
		}
	}
	cam, pending := int64(0), int64(0)
	db.QueryRow(`SELECT id FROM dhcp_clients WHERE mac = '02:00:00:00:00:01'`).Scan(&cam)
	db.QueryRow(`SELECT id FROM dhcp_clients WHERE mac = '02:00:00:00:00:02'`).Scan(&pending)
	_ = s.setClientApproved(cam, true)

	for _, id := range []int64{cam, pending, cam} { // the third call must keep cam's address
		if err := s.assignVPNIP(id); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := s.getClient(cam)
	p, _ := s.getClient(pending)
	if c.VPNIP != "10.8.128.3" || p.VPNIP != "10.8.128.4" {
		t.Fatalf("want the first free upper-half addresses 10.8.128.3 and .4, got %q and %q", c.VPNIP, p.VPNIP)
	}
	if _, err := db.Exec(`UPDATE dhcp_clients SET vpn_ip = ? WHERE id = ?`, c.VPNIP, pending); err == nil {
		t.Fatal("two devices must never share a VPN address")
	}

	// Policy and Headscale policy: only the approved device, one-way, at its own address.
	if err := s.setDeviceACL(cam, phone, false); err != nil {
		t.Fatal(err)
	}
	if err := s.setDeviceACL(pending, phone, true); err != nil {
		t.Fatal(err)
	}
	pol, err := s.networkPolicy(n)
	if err != nil || len(pol.Devices) != 1 || pol.Devices[0].VPNIP != "10.8.128.3" {
		t.Fatalf("the approved device must carry its VPN address: %+v %v", pol.Devices, err)
	}
	hs, err := HeadscaleGrants(db)
	if err != nil || len(hs) != 1 || hs[0] != (HeadscaleGrant{ClientID: phone, VPNIP: "10.8.128.3"}) {
		t.Fatalf("Headscale grants must mirror the firewall (approved device, one-way): %+v %v", hs, err)
	}
	if err := s.setDeviceACL(cam, phone, true); err != nil { // changing the direction updates the grant
		t.Fatal(err)
	}
	if hs, _ := HeadscaleGrants(db); len(hs) != 1 || !hs[0].Both {
		t.Fatalf("a grant made two-way must show as two-way: %+v", hs)
	}

	// Should a VPN client ever hold the same address, the device loses the swap, never the client.
	insert(`INSERT INTO vpn_clients (name, ip, type) VALUES ('late', '10.8.128.3', 'wireguard')`)
	if pol, _ := s.networkPolicy(n); pol.Devices[0].VPNIP != "" {
		t.Fatalf("an address also held by a VPN client must not be swapped: %+v", pol.Devices)
	}
	if hs, _ := HeadscaleGrants(db); len(hs) != 0 {
		t.Fatalf("nor put in the Headscale policy: %+v", hs)
	}

	// Without a WireGuard range there is nothing to hand out.
	t.Setenv("WG_IP_RANGE", "")
	db.Exec(`UPDATE dhcp_clients SET vpn_ip = '' WHERE id = ?`, pending)
	if err := s.assignVPNIP(pending); err != errNoVPNAddress {
		t.Fatalf("no WireGuard range must refuse the address, got %v", err)
	}
}
