package domains

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
)

// A route whose target is a LAN device's VPN address is linked to that device, in the statement
// that writes it; any other target is not, and retargeting a route re-links it. The list names the
// device, a VPN address nobody holds is flagged, and every change re-applies the firewall.
func TestRouteLinksToLANDevice(t *testing.T) {
	t.Setenv("TRAEFIK_CONFIG", t.TempDir()) // the route apply writes Traefik's config here
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("WG_SERVER_IP", "10.8.0.1")
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, _ := database.GetDB()
	for _, q := range []string{`DELETE FROM domain_routes`, `DELETE FROM dhcp_clients`, `DELETE FROM dhcp_networks`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	res, err := db.Exec(`INSERT INTO dhcp_networks (iface, cidr, gateway_ip, pool_start, pool_end) VALUES ('ens19', '10.20.20.0/24', '10.20.20.1', '10.20.20.50', '10.20.20.200')`)
	if err != nil {
		t.Fatal(err)
	}
	netID, _ := res.LastInsertId()
	res, err = db.Exec(`INSERT INTO dhcp_clients (network_id, mac, ip, name, approved, vpn_ip) VALUES (?, '02:00:00:00:00:01', '10.20.20.51', 'cam', 1, '10.8.128.1')`, netID)
	if err != nil {
		t.Fatal(err)
	}
	cam, _ := res.LastInsertId()
	db.Exec(`INSERT INTO dhcp_clients (network_id, mac, ip) VALUES (?, '02:00:00:00:00:02', '10.20.20.52')`, netID) // VPN access off

	applied := 0 // the firewall must follow every route change
	RoutesApplied = func() { applied++ }
	t.Cleanup(func() { RoutesApplied = func() {} })
	s := New()
	call := func(h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rr
	}
	create := func(domain, ip string) {
		if rr := call(s.handleCreate, http.MethodPost, "/api/domains", fmt.Sprintf(`{"domain":%q,"targetIp":%q,"targetPort":80}`, domain, ip)); rr.Code != http.StatusOK {
			t.Fatalf("create %s: %d %s", domain, rr.Code, rr.Body)
		}
	}
	linkOf := func(domain string) (id int64, ok bool) {
		var v *int64
		db.QueryRow(`SELECT lan_device_id FROM domain_routes WHERE domain = ?`, domain).Scan(&v)
		if v == nil {
			return 0, false
		}
		return *v, true
	}
	create("cam.example.com", "10.8.128.1")
	create("other.example.com", "10.8.0.5")
	create("empty.example.com", "10.8.128.2") // an address nobody holds — e.g. VPN access already off
	if applied != 3 {
		t.Fatalf("each route change must re-apply the firewall: %d of 3", applied)
	}
	if id, ok := linkOf("cam.example.com"); !ok || id != cam {
		t.Fatalf("a route to the device's VPN address must link to it: %v %v", id, ok)
	}
	for _, d := range []string{"other.example.com", "empty.example.com"} {
		if _, ok := linkOf(d); ok {
			t.Fatalf("%s must not link to a LAN device", d)
		}
	}
	rr := call(s.handleList, http.MethodGet, "/api/domains", "")
	var list struct {
		Routes []DomainRoute `json:"routes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	byDomain := map[string]DomainRoute{}
	for _, r := range list.Routes {
		byDomain[r.Domain] = r
	}
	if byDomain["cam.example.com"].LANDeviceName != "cam" {
		t.Fatalf("the list must name the device: %s", rr.Body)
	}
	// A VPN address nobody holds is flagged; a held one isn't.
	if byDomain["cam.example.com"].TargetUnheld || !byDomain["empty.example.com"].TargetUnheld || !byDomain["other.example.com"].TargetUnheld {
		t.Fatalf("unheld flags wrong: %+v", list.Routes)
	}

	// Retargeting re-links: away from the device unlinks, onto it links.
	var otherID int64
	db.QueryRow(`SELECT id FROM domain_routes WHERE domain = 'other.example.com'`).Scan(&otherID)
	var camRoute int64
	db.QueryRow(`SELECT id FROM domain_routes WHERE domain = 'cam.example.com'`).Scan(&camRoute)
	if rr := call(s.handleUpdate, http.MethodPut, fmt.Sprintf("/api/domains/%d", camRoute), `{"targetIp":"10.8.0.6"}`); rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body)
	}
	if _, ok := linkOf("cam.example.com"); ok {
		t.Fatal("a route moved off the device must unlink")
	}
	if rr := call(s.handleUpdate, http.MethodPut, fmt.Sprintf("/api/domains/%d", otherID), `{"targetIp":"10.8.128.1"}`); rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body)
	}
	if id, ok := linkOf("other.example.com"); !ok || id != cam {
		t.Fatal("a route moved onto the device must link")
	}
	if routes, err := LANDeviceRoutes(db, cam); err != nil || len(routes) != 1 || routes[0].Domain != "other.example.com" || routes[0].Port != 80 || routes[0].AccessMode != "vpn" {
		t.Fatalf("LANDeviceRoutes: %+v %v", routes, err)
	}
}

// A route can't take over the panel's own domain or point at its internals, and a public route
// (created, made public, or switched back on) asks for a step-up first.
func TestRouteGuards(t *testing.T) {
	t.Setenv("TRAEFIK_CONFIG", t.TempDir())
	t.Setenv("SSL_DOMAIN", "panel.example.com")
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, _ := database.GetDB()
	db.Exec(`DELETE FROM domain_routes`)
	RoutesApplied = func() {}
	s := New()
	call := func(h http.HandlerFunc, method, path, body string) int {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rr.Code
	}
	create := func(body string) int { return call(s.handleCreate, http.MethodPost, "/api/domains", body) }
	if c := create(`{"domain":"panel.example.com","targetIp":"192.0.2.10","targetPort":80}`); c != http.StatusBadRequest {
		t.Errorf("the panel's own domain: %d", c)
	}
	if c := create(`{"domain":"x.example.com","targetIp":"127.0.0.1","targetPort":80}`); c != http.StatusBadRequest {
		t.Errorf("loopback target: %d", c)
	}
	if c := create(`{"domain":"pub.example.com","targetIp":"192.0.2.10","targetPort":80,"accessMode":"public"}`); c != http.StatusPreconditionRequired {
		t.Errorf("public route without step-up: %d", c)
	}
	if c := create(`{"domain":"vpn.example.com","targetIp":"192.0.2.10","targetPort":80}`); c != http.StatusOK {
		t.Fatalf("a VPN-only route needs no step-up: %d", c)
	}
	var id int64
	db.QueryRow(`SELECT id FROM domain_routes WHERE domain = 'vpn.example.com'`).Scan(&id)
	path := fmt.Sprintf("/api/domains/%d", id)
	if c := call(s.handleUpdate, http.MethodPut, path, `{"accessMode":"public"}`); c != http.StatusPreconditionRequired {
		t.Errorf("making it public without step-up: %d", c)
	}
	if c := call(s.handleUpdate, http.MethodPut, path, `{"targetIp":"169.254.169.254"}`); c != http.StatusBadRequest {
		t.Errorf("retargeting to metadata: %d", c)
	}
	db.Exec(`UPDATE domain_routes SET access_mode = 'public', enabled = 0 WHERE id = ?`, id)
	if c := call(s.handleToggle, http.MethodPost, path+"/toggle", ``); c != http.StatusPreconditionRequired {
		t.Errorf("switching a public route back on without step-up: %d", c)
	}
}
