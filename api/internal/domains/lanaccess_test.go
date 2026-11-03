package domains

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/router"
)

// lanFixture is a clean DB with one enabled and one disabled LAN network and devices in every
// state; it returns the device IDs by name.
func lanFixture(t *testing.T) (*database.DB, map[string]int64) {
	t.Helper()
	t.Setenv("TRAEFIK_CONFIG", t.TempDir())
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
	net := func(iface, cidr string, enabled int) int64 {
		res, err := db.Exec(`INSERT INTO dhcp_networks (iface, cidr, gateway_ip, pool_start, pool_end, enabled) VALUES (?, ?, '', '', '', ?)`, iface, cidr, enabled)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	on, off := net("ens19", "10.20.20.0/24", 1), net("ens20", "10.30.30.0/24", 0)
	ids := map[string]int64{}
	for i, d := range []struct {
		name              string
		network           int64
		approved, blocked int
	}{
		{"laptop", on, 1, 0}, {"desktop", on, 1, 0}, {"pending", on, 0, 0}, {"blocked", on, 1, 1}, {"offnet", off, 1, 0},
	} {
		res, err := db.Exec(`INSERT INTO dhcp_clients (network_id, mac, ip, name, approved, blocked) VALUES (?, ?, ?, ?, ?, ?)`,
			d.network, fmt.Sprintf("02:00:00:00:00:%02x", i+1), fmt.Sprintf("10.20.20.%d", 51+i), d.name, d.approved, d.blocked)
		if err != nil {
			t.Fatal(err)
		}
		ids[d.name], _ = res.LastInsertId()
	}
	return db, ids
}

// Who a private route lets in: every approved, unblocked device on an enabled network when it
// lets all in, else only those picked that are; never through a public or a switched-off route.
func TestLANRouteAccess(t *testing.T) {
	db, ids := lanFixture(t)
	// An approved device whose address is outside its network (stale) lets nothing in.
	if _, err := db.Exec(`INSERT INTO dhcp_clients (network_id, mac, ip, approved) SELECT network_id, '02:00:00:00:00:99', '192.0.2.9', 1 FROM dhcp_clients WHERE id = ?`, ids["laptop"]); err != nil {
		t.Fatal(err)
	}
	route := func(domain, mode string, enabled, all int, picked ...string) {
		res, err := db.Exec(`INSERT INTO domain_routes (domain, target_ip, target_port, access_mode, enabled, lan_all) VALUES (?, '10.8.0.9', 80, ?, ?, ?)`, domain, mode, enabled, all)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		for _, p := range picked {
			if _, err := db.Exec(`INSERT INTO domain_route_lan_devices (route_id, device_id) VALUES (?, ?)`, id, ids[p]); err != nil {
				t.Fatal(err)
			}
		}
	}
	route("all.example.com", "vpn", 1, 1)
	route("picked.example.com", "vpn", 1, 0, "desktop", "pending", "blocked", "offnet")
	route("public.example.com", "public", 1, 1, "laptop")
	route("off.example.com", "vpn", 0, 1)
	route("closed.example.com", "vpn", 1, 0)

	access, err := db.LANRouteAccess()
	if err != nil {
		t.Fatal(err)
	}
	names := func(domain string) (out []int64) {
		for _, d := range access[domain] {
			out = append(out, d.ID)
		}
		return out
	}
	if got, want := names("all.example.com"), []int64{ids["laptop"], ids["desktop"]}; !slices.Equal(got, want) {
		t.Fatalf("all: got %v, want %v", got, want)
	}
	if got, want := names("picked.example.com"), []int64{ids["desktop"]}; !slices.Equal(got, want) {
		t.Fatalf("picked: got %v, want %v", got, want)
	}
	for _, d := range []string{"public.example.com", "off.example.com", "closed.example.com"} {
		if _, ok := access[d]; ok {
			t.Fatalf("%s must let no LAN device in: %v", d, access[d])
		}
	}
	if d := access["picked.example.com"][0]; d.Iface != "ens19" || d.IP != "10.20.20.52" {
		t.Fatalf("device details: %+v", d)
	}
	devs, err := db.LANRouteDevices()
	if err != nil || len(devs) != 2 || devs[0].ID != ids["laptop"] || devs[1].ID != ids["desktop"] {
		t.Fatalf("union: %+v %v", devs, err)
	}
}

// Letting LAN devices in asks for a step-up; keeping or narrowing it doesn't. A public route keeps
// no LAN access. The Traefik routes follow: the route gets its own gate with the devices' addresses.
func TestRouteLANAccessHandlers(t *testing.T) {
	db, ids := lanFixture(t)
	stepUps := 0
	router.SetStepUpFunc(func(w http.ResponseWriter, r *http.Request) bool { stepUps++; return true })
	t.Cleanup(func() { router.SetStepUpFunc(nil) })
	RoutesApplied = func() {}
	s := New()
	call := func(h http.HandlerFunc, method, path, body string) {
		t.Helper()
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s %s %s: %d %s", method, path, body, rr.Code, rr.Body)
		}
	}
	access := func(id int64) lanAccess {
		a, err := loadLANAccess(db, int(id))
		if err != nil {
			t.Fatal(err)
		}
		return a[int(id)]
	}
	routesFile := func() string {
		b, _ := os.ReadFile(filepath.Join(os.Getenv("TRAEFIK_CONFIG"), "domains.yml"))
		return string(b)
	}

	call(s.handleCreate, http.MethodPost, "/api/domains", `{"domain":"git.example.com","targetIp":"10.8.0.9","targetPort":3000,"lanAll":true}`)
	var id int64
	db.QueryRow(`SELECT id FROM domain_routes WHERE domain = 'git.example.com'`).Scan(&id)
	if a := access(id); !a.All || stepUps != 1 {
		t.Fatalf("create with every LAN device: %+v, step-ups %d", a, stepUps)
	}
	if f := routesFile(); !strings.Contains(f, "sentinel_lan-") || !strings.Contains(f, `"10.20.20.51/32"`) || !strings.Contains(f, `"10.20.20.52/32"`) {
		t.Fatalf("the route's own gate must list the approved devices:\n%s", f)
	}

	path := fmt.Sprintf("/api/domains/%d", id)
	call(s.handleUpdate, http.MethodPut, path, fmt.Sprintf(`{"lanAll":false,"lanDevices":[%d]}`, ids["desktop"]))
	if a := access(id); a.All || !slices.Equal(a.Devices, []int64{ids["desktop"]}) || stepUps != 1 {
		t.Fatalf("narrowing must not ask: %+v, step-ups %d", a, stepUps)
	}
	if f := routesFile(); strings.Contains(f, `"10.20.20.51/32"`) {
		t.Fatalf("a device no longer picked is still let in:\n%s", f)
	}
	call(s.handleUpdate, http.MethodPut, path, fmt.Sprintf(`{"lanDevices":[%d,%d]}`, ids["laptop"], ids["desktop"]))
	if stepUps != 2 {
		t.Fatalf("adding a device must ask, step-ups %d", stepUps)
	}
	call(s.handleUpdate, http.MethodPut, path, `{"description":"code"}`)
	if stepUps != 2 {
		t.Fatalf("an unrelated change must not ask, step-ups %d", stepUps)
	}

	// Off and on again with LAN devices let in asks again.
	call(s.handleToggle, http.MethodPost, path+"/toggle", `{}`)
	call(s.handleToggle, http.MethodPost, path+"/toggle", `{}`)
	if stepUps != 3 {
		t.Fatalf("switching back on must ask, step-ups %d", stepUps)
	}

	// Public: asked for anyway, and keeps no LAN access.
	call(s.handleUpdate, http.MethodPut, path, `{"accessMode":"public"}`)
	if a := access(id); a.isOpen() {
		t.Fatalf("a public route kept LAN access: %+v", a)
	}

	// Unknown devices are refused.
	rr := httptest.NewRecorder()
	s.handleCreate(rr, httptest.NewRequest(http.MethodPost, "/api/domains", strings.NewReader(`{"domain":"x.example.com","targetIp":"10.8.0.9","targetPort":80,"lanDevices":[999999]}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown device: %d %s", rr.Code, rr.Body)
	}
}

func TestLANAccessWidens(t *testing.T) {
	cases := []struct {
		old, now lanAccess
		want     bool
	}{
		{lanAccess{}, lanAccess{All: true}, true},
		{lanAccess{}, lanAccess{Devices: []int64{1}}, true},
		{lanAccess{Devices: []int64{1}}, lanAccess{Devices: []int64{1, 2}}, true},
		{lanAccess{Devices: []int64{1, 2}}, lanAccess{Devices: []int64{2}}, false},
		{lanAccess{All: true}, lanAccess{Devices: []int64{3}}, false},
		{lanAccess{All: true}, lanAccess{All: true}, false},
		{lanAccess{Devices: []int64{1}}, lanAccess{}, false},
	}
	for i, c := range cases {
		if got := c.now.widens(c.old); got != c.want {
			t.Errorf("case %d: %+v -> %+v widens = %v, want %v", i, c.old, c.now, got, c.want)
		}
	}
	if (lanAccess{All: true, Devices: []int64{1}}).forMode("public").isOpen() {
		t.Error("a public route must keep no LAN access")
	}
}
