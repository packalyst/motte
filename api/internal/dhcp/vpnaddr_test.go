package dhcp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/router"
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
	got := renderReachability(nets, pol, "eth0", testPrivateRanges, routeOrigin{})
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
	if ok, err := s.setDeviceACL(cam, phone, false); !ok || err != nil {
		t.Fatal(err)
	}
	if ok, err := s.setDeviceACL(pending, phone, true); !ok || err != nil {
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
	if ok, err := s.setDeviceACL(cam, phone, true); !ok || err != nil { // changing the direction updates the grant
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

// VPN access is switched on and off with a step-up either way. On gives the device its VPN address;
// off removes the address and every grant together; a grant needs VPN access on.
func TestVPNAccessSwitch(t *testing.T) {
	t.Setenv("PATH", "") // the handlers re-apply the network: never run iptables/ip on the test host
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("WG_SERVER_IP", "10.8.0.1")
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, _ := database.GetDB()
	for _, q := range []string{`DELETE FROM dhcp_client_acl`, `DELETE FROM dhcp_clients`, `DELETE FROM dhcp_networks`, `DELETE FROM vpn_virtual_ips`, `DELETE FROM vpn_clients`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{db: db}
	n := &Network{Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", PoolStart: "10.20.20.50",
		PoolEnd: "10.20.20.200", LeaseSecs: 3600, Mode: "approve", Enabled: true}
	var err error
	if n.ID, err = s.createNetwork(n); err != nil {
		t.Fatal(err)
	}
	if err := s.upsertClient(n.ID, "02:00:00:00:00:01", "10.20.20.51", "", true); err != nil {
		t.Fatal(err)
	}
	var dev int64
	db.QueryRow(`SELECT id FROM dhcp_clients`).Scan(&dev)
	res, _ := db.Exec(`INSERT INTO vpn_clients (name, ip, type) VALUES ('laptop', '10.8.0.2', 'wireguard')`)
	laptop, _ := res.LastInsertId()

	stepUpOK := false
	router.SetStepUpFunc(func(w http.ResponseWriter, _ *http.Request) bool {
		if !stepUpOK {
			w.WriteHeader(http.StatusPreconditionRequired)
		}
		return stepUpOK
	})
	t.Cleanup(func() { router.SetStepUpFunc(nil) })
	call := func(h http.HandlerFunc, method, path, body string) int {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rr.Code
	}
	vpn := func(on bool) int {
		return call(s.handleSetVPNAccess, http.MethodPut, fmt.Sprintf("/api/dhcp/clients/%d/vpn", dev), fmt.Sprintf(`{"enabled":%v}`, on))
	}
	grant := func() int {
		return call(s.handleAddDeviceACL, http.MethodPost, fmt.Sprintf("/api/dhcp/clients/%d/acl", dev), fmt.Sprintf(`{"client_id":%d}`, laptop))
	}
	state := func() (ip string, grants int) {
		db.QueryRow(`SELECT vpn_ip FROM dhcp_clients WHERE id = ?`, dev).Scan(&ip)
		db.QueryRow(`SELECT COUNT(*) FROM dhcp_client_acl WHERE device_id = ?`, dev).Scan(&grants)
		return
	}

	if code := grant(); code != http.StatusConflict {
		t.Fatalf("a grant without VPN access: %d, want 409", code)
	}
	if code := vpn(true); code != http.StatusPreconditionRequired {
		t.Fatalf("switching on without step-up: %d", code)
	}
	if ip, _ := state(); ip != "" {
		t.Fatalf("no step-up, no address: got %q", ip)
	}
	stepUpOK = true
	if code := vpn(true); code != http.StatusOK {
		t.Fatalf("switching on: %d", code)
	}
	if code := grant(); code != http.StatusOK {
		t.Fatalf("a grant with VPN access on: %d", code)
	}
	if ip, g := state(); ip == "" || g != 1 {
		t.Fatalf("on: want an address and the grant, got %q, %d", ip, g)
	}

	stepUpOK = false
	if code := vpn(false); code != http.StatusPreconditionRequired {
		t.Fatalf("switching off without step-up: %d", code)
	}
	if ip, g := state(); ip == "" || g != 1 {
		t.Fatalf("no step-up, nothing removed: got %q, %d", ip, g)
	}
	stepUpOK = true
	if code := vpn(false); code != http.StatusOK {
		t.Fatalf("switching off: %d", code)
	}
	if ip, g := state(); ip != "" || g != 0 {
		t.Fatalf("off must remove the address and every grant, got %q, %d", ip, g)
	}

	// A blocked device can't be switched on.
	_ = s.setClientBlocked(dev, true, false)
	if code := vpn(true); code != http.StatusConflict {
		t.Fatalf("switching a blocked device on: %d", code)
	}
}

// A domain route lets Traefik, and only Traefik, reach the device on the route's ports through the
// VPN address: from Traefik's own address on its own bridge, and the forward rule only takes what
// came through that swap. Nothing opens when the origin is unknown, the port is invalid or the
// device has no usable VPN address, and a route needs no grant.
func TestReachabilityDomainRoutes(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", Mode: "approve", Enabled: true}}
	pol := map[int64]netPolicy{1: {Devices: []devicePolicy{
		{IP: "10.20.20.51", MAC: "02:00:00:00:00:51", VPNIP: "10.8.128.1", Routes: []int{80, 443}}, // no grant: route only
		{IP: "10.20.20.52", MAC: "02:00:00:00:00:52", VPNIP: "10.8.128.2", Routes: []int{0, 70000}},
		{IP: "10.20.20.53", MAC: "02:00:00:00:00:53", Routes: []int{80}}, // no usable VPN address
	}}}
	origin := routeOrigin{Iface: "br-0123456789ab", IP: "172.18.0.2"}
	got := renderReachability(nets, pol, "eth0", testPrivateRanges, origin)
	for _, want := range []string{
		`iifname "br-0123456789ab" ip saddr 172.18.0.2 ip daddr 10.8.128.1 tcp dport { 80, 443 } dnat ip to 10.20.20.51`,
		`iifname "br-0123456789ab" ip saddr 172.18.0.2 ip daddr 10.20.20.51 tcp dport { 80, 443 } ct status dnat accept`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{
		`iifname { "wg0", "tailscale0" } ip daddr 10.8.128.1`, // a route opens nothing to VPN clients
		`10.8.128.2`,             // no valid port: nothing
		`dnat ip to 10.20.20.53`, // no VPN address: nothing
	} {
		if strings.Contains(got, bad) {
			t.Fatalf("must not contain %q:\n%s", bad, got)
		}
	}
	// The route rules sit above the network's default drop.
	if strings.Index(got, "ct status dnat accept") > strings.Index(got, "ip daddr 10.20.20.0/24 drop") {
		t.Fatalf("the route rule must come before the default drop:\n%s", got)
	}
	for _, o := range []routeOrigin{{}, {Iface: "br-0123456789ab"}, {IP: "172.18.0.2"}, {Iface: "bad iface", IP: "172.18.0.2"}, {Iface: "br-0123456789ab", IP: "not-an-ip"}} {
		if out := renderReachability(nets, pol, "eth0", testPrivateRanges, o); strings.Contains(out, "tcp dport") {
			t.Fatalf("origin %+v must open nothing:\n%s", o, out)
		}
	}
}

// Domain routes follow the device: the firewall opens only enabled routes to its current VPN
// address, and turning VPN access off, forgetting the device or deleting its network removes them
// in the same change as the address.
func TestLANDeviceRoutesFollowDevice(t *testing.T) {
	t.Setenv("PATH", "") // the handlers re-apply the network: never run iptables/ip on the test host
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("WG_SERVER_IP", "10.8.0.1")
	t.Setenv("TRAEFIK_CONFIG", t.TempDir()) // the route apply writes Traefik's config here
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, _ := database.GetDB()
	for _, q := range []string{`DELETE FROM domain_routes`, `DELETE FROM dhcp_client_acl`, `DELETE FROM dhcp_clients`, `DELETE FROM dhcp_networks`, `DELETE FROM vpn_virtual_ips`, `DELETE FROM vpn_clients`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{db: db}
	n := &Network{Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", PoolStart: "10.20.20.50",
		PoolEnd: "10.20.20.200", LeaseSecs: 3600, Mode: "approve", Enabled: true}
	var err error
	if n.ID, err = s.createNetwork(n); err != nil {
		t.Fatal(err)
	}
	devs := map[string]int64{}
	for _, mac := range []string{"02:00:00:00:00:01", "02:00:00:00:00:02"} {
		if err := s.upsertClient(n.ID, mac, "10.20.20.5"+mac[len(mac)-1:], "", true); err != nil {
			t.Fatal(err)
		}
		var id int64
		db.QueryRow(`SELECT id FROM dhcp_clients WHERE mac = ?`, mac).Scan(&id)
		if err := s.assignVPNIP(id); err != nil {
			t.Fatal(err)
		}
		devs[mac] = id
	}
	cam, nvr := devs["02:00:00:00:00:01"], devs["02:00:00:00:00:02"]
	route := func(domain, ip string, port int, dev int64, enabled bool) {
		if _, err := db.Exec(`INSERT INTO domain_routes (domain, target_ip, target_port, lan_device_id, enabled) VALUES (?,?,?,?,?)`,
			domain, ip, port, dev, enabled); err != nil {
			t.Fatal(err)
		}
	}
	camIP, nvrIP := "", ""
	db.QueryRow(`SELECT vpn_ip FROM dhcp_clients WHERE id = ?`, cam).Scan(&camIP)
	db.QueryRow(`SELECT vpn_ip FROM dhcp_clients WHERE id = ?`, nvr).Scan(&nvrIP)
	route("cam.example.test", camIP, 80, cam, true)
	route("cam-admin.example.test", camIP, 443, cam, false)     // disabled: opens nothing
	route("cam-old.example.test", "10.8.128.99", 81, cam, true) // not its VPN address: opens nothing
	route("nvr.example.test", nvrIP, 8080, nvr, true)

	pol, err := s.networkPolicy(n)
	if err != nil {
		t.Fatal(err)
	}
	ports := map[string][]int{}
	for _, d := range pol.Devices {
		ports[d.IP] = d.Routes
	}
	if fmt.Sprint(ports["10.20.20.51"]) != "[80]" || fmt.Sprint(ports["10.20.20.52"]) != "[8080]" {
		t.Fatalf("only enabled routes to the current VPN address open: %v", ports)
	}

	routesOf := func(dev int64) int {
		var c int
		db.QueryRow(`SELECT COUNT(*) FROM domain_routes WHERE lan_device_id = ?`, dev).Scan(&c)
		return c
	}
	// VPN access off takes the device's routes with it, and nobody else's.
	router.SetStepUpFunc(func(http.ResponseWriter, *http.Request) bool { return true })
	t.Cleanup(func() { router.SetStepUpFunc(nil) })
	rr := httptest.NewRecorder()
	s.handleSetVPNAccess(rr, httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/dhcp/clients/%d/vpn", cam), strings.NewReader(`{"enabled":false}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("switching off: %d %s", rr.Code, rr.Body)
	}
	if routesOf(cam) != 0 || routesOf(nvr) != 1 {
		t.Fatalf("off must remove the device's routes only: cam %d, nvr %d", routesOf(cam), routesOf(nvr))
	}

	// Forgetting a device removes its routes.
	if _, err := s.deleteClient(nvr); err != nil || routesOf(nvr) != 0 {
		t.Fatalf("forgetting the device must remove its routes: %d %v", routesOf(nvr), err)
	}

	// Deleting a network removes the routes to its devices.
	if err := s.upsertClient(n.ID, "02:00:00:00:00:03", "10.20.20.53", "", true); err != nil {
		t.Fatal(err)
	}
	var third int64
	db.QueryRow(`SELECT id FROM dhcp_clients WHERE mac = '02:00:00:00:00:03'`).Scan(&third)
	route("third.example.test", "10.8.128.50", 80, third, true)
	removed, err := s.deleteNetwork(n.ID)
	if err != nil || len(removed) != 1 || removed[0].Domain != "third.example.test" {
		t.Fatalf("deleting the network must report its routes: %+v %v", removed, err)
	}
	var left int
	db.QueryRow(`SELECT COUNT(*) FROM domain_routes`).Scan(&left)
	if left != 0 {
		t.Fatalf("routes left after the network went: %d", left)
	}
}

// Taking access away cuts the device's open connections: after an apply, every device that lost
// a path (a grant, the way back, a route port, the internet, its VPN address) or is gone has its
// addresses handed to the conntrack flush; a device that only gained or kept access is left alone,
// and the first apply after start cuts nothing.
func TestReachabilityCutsLostAccess(t *testing.T) {
	nets := []Network{{ID: 1, Iface: "ens19", CIDR: "10.20.20.0/24", Mode: "approve", Enabled: true}}
	origin := routeOrigin{Iface: "br-0123456789ab", IP: "172.18.0.2"}
	dev := func(n int, d devicePolicy) devicePolicy {
		d.IP, d.MAC = fmt.Sprintf("10.20.20.%d", 50+n), fmt.Sprintf("02:00:00:00:00:%02d", n)
		return d
	}
	before := map[int64]netPolicy{1: {Devices: []devicePolicy{
		dev(1, devicePolicy{VPNIP: "10.8.128.1", Allowed: []vpnGrant{{IP: "10.8.0.7"}}}),             // loses the grant
		dev(2, devicePolicy{VPNIP: "10.8.128.2", Allowed: []vpnGrant{{IP: "10.8.0.7", Both: true}}}), // two-way → one-way
		dev(3, devicePolicy{VPNIP: "10.8.128.3", Routes: []int{80, 443}}),                            // loses a route port
		dev(4, devicePolicy{Internet: true}),                                                         // loses the internet
		dev(5, devicePolicy{VPNIP: "10.8.128.5"}),                                                    // gone (blocked/forgotten)
		dev(6, devicePolicy{VPNIP: "10.8.128.6", Allowed: []vpnGrant{{IP: "10.8.0.7"}}}),             // keeps everything
		dev(7, devicePolicy{}), // only gains
	}}}
	after := map[int64]netPolicy{1: {Devices: []devicePolicy{
		dev(1, devicePolicy{VPNIP: "10.8.128.1"}),
		dev(2, devicePolicy{VPNIP: "10.8.128.2", Allowed: []vpnGrant{{IP: "10.8.0.7"}}}),
		dev(3, devicePolicy{VPNIP: "10.8.128.3", Routes: []int{80}}),
		dev(4, devicePolicy{}),
		dev(6, devicePolicy{VPNIP: "10.8.128.6", Allowed: []vpnGrant{{IP: "10.8.0.7"}}}),
		dev(7, devicePolicy{VPNIP: "10.8.128.7", Allowed: []vpnGrant{{IP: "10.8.0.7"}}, Internet: true}),
	}}}
	tbl := &ReachabilityTable{}
	tbl.built = accessOf(nets, before, "eth0", origin)
	if got := tbl.ConntrackFlushTargets(); len(got) != 0 {
		t.Fatalf("the first apply must cut nothing: %v", got)
	}
	tbl.built = accessOf(nets, after, "eth0", origin)
	got := map[string]bool{}
	for _, ip := range tbl.ConntrackFlushTargets() {
		got[ip] = true
	}
	for _, ip := range []string{"10.20.20.51", "10.8.128.1", "10.20.20.52", "10.8.128.2", "10.20.20.53", "10.8.128.3", "10.20.20.54", "10.20.20.55", "10.8.128.5"} {
		if !got[ip] {
			t.Errorf("%s lost access but its connections stay: %v", ip, got)
		}
	}
	for _, ip := range []string{"10.20.20.56", "10.8.128.6", "10.20.20.57", "10.8.128.7"} {
		if got[ip] {
			t.Errorf("%s lost nothing but its connections are cut: %v", ip, got)
		}
	}
	// Applied again unchanged: nothing more to cut.
	if again := tbl.ConntrackFlushTargets(); len(again) != 0 {
		t.Fatalf("an unchanged apply must cut nothing: %v", again)
	}
	// Traefik's origin going away closes every route: those devices lose access too.
	tbl.built = accessOf(nets, after, "eth0", routeOrigin{})
	if cut := tbl.ConntrackFlushTargets(); fmt.Sprint(cut) != "[10.20.20.53 10.8.128.3]" {
		t.Fatalf("routes shut by a lost origin must cut the device: %v", cut)
	}
}
