package domains

import (
	"database/sql"
	"log"

	"api/internal/adguard"
	"api/internal/database"
	"api/internal/helper"
)

// lanDeviceByVPNIP resolves a route's target to the LAN device whose VPN address it is (NULL for any
// other target). It runs inside the statement that writes the route, so a device whose VPN access
// goes off at that moment can't be linked through a stale read.
const lanDeviceByVPNIP = `(SELECT id FROM dhcp_clients WHERE vpn_ip = ? AND vpn_ip <> '')`

// vpnDNSTarget is the address VPN-only domains resolve to: the box's WireGuard address.
func vpnDNSTarget() string { return helper.GetEnvOptional("WG_SERVER_IP", "10.8.0.1") }

// LANRoute is a domain route to a LAN device, as listed before its VPN access is turned off.
type LANRoute struct {
	Domain     string `json:"domain"`
	Port       int    `json:"port"`
	AccessMode string `json:"access_mode"`
}

// LANDeviceRoutes lists the domain routes to a LAN device.
func LANDeviceRoutes(db *database.DB, deviceID int64) ([]LANRoute, error) {
	rows, err := db.Query(`SELECT domain, target_port, COALESCE(NULLIF(access_mode, ''), 'vpn')
		FROM domain_routes WHERE lan_device_id = ? ORDER BY domain`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LANRoute{}
	for rows.Next() {
		var r LANRoute
		if err := rows.Scan(&r.Domain, &r.Port, &r.AccessMode); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Removed lists routes deleted from the database whose DNS rewrites and Traefik config still have to
// follow; Apply does that once the deleting transaction has committed.
type Removed []LANRoute

// DeleteLANDeviceRoutes deletes a LAN device's routes as part of tx.
func DeleteLANDeviceRoutes(tx *sql.Tx, deviceID int64) (Removed, error) {
	return deleteRoutes(tx, `lan_device_id = ?`, deviceID)
}

// DeleteLANNetworkRoutes deletes the routes to every device of a LAN network as part of tx.
func DeleteLANNetworkRoutes(tx *sql.Tx, networkID int64) (Removed, error) {
	return deleteRoutes(tx, `lan_device_id IN (SELECT id FROM dhcp_clients WHERE network_id = ?)`, networkID)
}

// deleteRoutes deletes the routes matching where (a constant from this package, never input) and
// returns them.
func deleteRoutes(tx *sql.Tx, where string, arg any) (Removed, error) {
	rows, err := tx.Query(`SELECT domain, target_port, COALESCE(NULLIF(access_mode, ''), 'vpn') FROM domain_routes WHERE `+where, arg)
	if err != nil {
		return nil, err
	}
	var out Removed
	for rows.Next() {
		var r LANRoute
		if err := rows.Scan(&r.Domain, &r.Port, &r.AccessMode); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(`DELETE FROM domain_routes WHERE `+where, arg); err != nil {
		return nil, err
	}
	return out, nil
}

// Domains names the removed routes, for audit messages.
func (r Removed) Domains() []string {
	out := make([]string, len(r))
	for i := range r {
		out[i] = r[i].Domain
	}
	return out
}

// Apply drops the removed VPN-only routes' DNS rewrites (as deleting one route does) and regenerates the Traefik config.
// Best-effort (logged): the rows are already gone, so the next apply converges either way.
func (r Removed) Apply() {
	if len(r) == 0 {
		return
	}
	target := vpnDNSTarget()
	for _, x := range r {
		if x.AccessMode != "vpn" {
			continue
		}
		if err := adguard.DeleteDomainRewrite(x.Domain, target); err != nil {
			log.Printf("domains: could not drop the DNS rewrite for %s: %v", x.Domain, err)
		}
	}
	if err := ApplyRoutes(); err != nil {
		log.Printf("domains: could not apply routes after removing %d: %v", len(r), err)
	}
}
