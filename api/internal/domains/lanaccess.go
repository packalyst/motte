package domains

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"

	"api/internal/database"
	"api/internal/events"
	"api/internal/router"
)

// LAN access to a private route: lan_all lets every approved LAN device use it, else only the
// devices picked for it (domain_route_lan_devices). A public route never keeps any: it is open
// to everyone already, and switching it back to private starts closed again.

// maxLANDevices caps the devices picked for one route.
const maxLANDevices = 256

// lanAccess is a route's LAN access as stored.
type lanAccess struct {
	All     bool
	Devices []int64
}

// isOpen reports whether any LAN device may use the route.
func (a lanAccess) isOpen() bool { return a.All || len(a.Devices) > 0 }

// widens reports whether a lets in a LAN device that old didn't: every one now, or one not
// picked before. Only that asks for a step-up; taking access away never does.
func (a lanAccess) widens(old lanAccess) bool {
	if a.All && !old.All {
		return true
	}
	return !old.All && slices.ContainsFunc(a.Devices, func(id int64) bool { return !slices.Contains(old.Devices, id) })
}

// forMode is what a route in mode keeps: nothing when it's public.
func (a lanAccess) forMode(mode string) lanAccess {
	if mode != "vpn" {
		return lanAccess{}
	}
	return a
}

// describe says who the access lets in, for the audit trail.
func (a lanAccess) describe() string {
	switch {
	case a.All:
		return "every approved LAN device"
	case len(a.Devices) > 0:
		return fmt.Sprintf("%d picked LAN device(s)", len(a.Devices))
	}
	return "no LAN device"
}

// checkLANDevices de-duplicates the picked device IDs and checks each is a known LAN device.
func checkLANDevices(db *database.DB, ids []int64) ([]int64, error) {
	var out []int64
	for _, id := range ids {
		if id <= 0 {
			return nil, errors.New("invalid LAN device id")
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out) // the order they are stored and compared in
	if len(out) > maxLANDevices {
		return nil, fmt.Errorf("at most %d LAN devices per route", maxLANDevices)
	}
	if len(out) == 0 {
		return nil, nil
	}
	args := make([]any, len(out))
	for i, id := range out {
		args[i] = id
	}
	var n int
	q := `SELECT COUNT(*) FROM dhcp_clients WHERE id IN (?` + strings.Repeat(",?", len(out)-1) + `)`
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		return nil, err
	}
	if n != len(out) {
		return nil, errors.New("unknown LAN device")
	}
	return out, nil
}

// loadLANAccess reads the LAN access of one route, or of every route when id is 0.
func loadLANAccess(db *database.DB, id int) (map[int]lanAccess, error) {
	q := `SELECT r.id, r.lan_all, p.device_id FROM domain_routes r
		LEFT JOIN domain_route_lan_devices p ON p.route_id = r.id`
	var args []any
	if id != 0 {
		q += ` WHERE r.id = ?`
		args = append(args, id)
	}
	rows, err := db.Query(q+` ORDER BY r.id, p.device_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]lanAccess{}
	for rows.Next() {
		var rid int
		var all bool
		var dev sql.NullInt64
		if err := rows.Scan(&rid, &all, &dev); err != nil {
			return nil, err
		}
		a := out[rid]
		a.All = all
		if dev.Valid {
			a.Devices = append(a.Devices, dev.Int64)
		}
		out[rid] = a
	}
	return out, rows.Err()
}

// withLANAccess fills in the routes' LAN access (of every route when id is 0, else of that one);
// false after it has answered with an error.
func withLANAccess(w http.ResponseWriter, db *database.DB, id int, routes []DomainRoute) bool {
	access, err := loadLANAccess(db, id)
	if err != nil {
		router.DBError(w, err)
		return false
	}
	for i := range routes {
		a := access[routes[i].ID]
		routes[i].LANAll, routes[i].LANDevices = a.All, a.Devices
		if routes[i].LANDevices == nil {
			routes[i].LANDevices = []int64{}
		}
	}
	return true
}

// saveLANAccess stores a route's LAN access in tx, replacing what it had.
func saveLANAccess(tx *sql.Tx, id int64, a lanAccess) error {
	if _, err := tx.Exec(`UPDATE domain_routes SET lan_all = ? WHERE id = ?`, a.All, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM domain_route_lan_devices WHERE route_id = ?`, id); err != nil {
		return err
	}
	for _, dev := range a.Devices {
		if _, err := tx.Exec(`INSERT INTO domain_route_lan_devices (route_id, device_id) VALUES (?, ?)`, id, dev); err != nil {
			return err
		}
	}
	return nil
}

// auditLANAccess records a change to who on the LANs may use a route.
func auditLANAccess(r *http.Request, domain string, old, now lanAccess) {
	if old.All == now.All && slices.Equal(old.Devices, now.Devices) {
		return
	}
	events.AuditRequest(r, "domains", "route_lan_access", fmt.Sprintf("%s: LAN access now %s (was %s)", domain, now.describe(), old.describe()))
}

// lanSources maps each private route LAN devices may use to their addresses, for the Traefik
// routes; the signature lets SyncLANAccess tell whether they changed since the last apply.
func lanSources(db *database.DB) (map[string][]string, string, error) {
	access, err := db.LANRouteAccess()
	if err != nil {
		return nil, "", err
	}
	out := make(map[string][]string, len(access))
	domains := make([]string, 0, len(access))
	for domain, devs := range access {
		for _, d := range devs {
			out[domain] = append(out[domain], d.IP)
		}
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	var sig strings.Builder
	for _, d := range domains {
		sig.WriteString(d + "=" + strings.Join(out[d], ",") + ";")
	}
	return out, sig.String(), nil
}

var (
	lanMu      sync.Mutex
	appliedLAN string // the LAN sources the Traefik routes were last written with
)

// SyncLANAccess rewrites the Traefik routes when the LAN devices that may use a private route
// changed (one approved, blocked, deleted or moved to another address; a network switched off),
// and does nothing otherwise, so it is safe to call on every LAN change.
func SyncLANAccess() {
	db, err := database.GetDB()
	if err != nil {
		return
	}
	_, sig, err := lanSources(db)
	if err != nil {
		log.Printf("domains: LAN access: %v", err)
		return
	}
	lanMu.Lock()
	same := sig == appliedLAN
	lanMu.Unlock()
	if same {
		return
	}
	if err := ApplyRoutes(); err != nil {
		log.Printf("domains: apply routes after a LAN change: %v", err)
	}
}
