package database

import (
	"net/netip"
	"sort"
)

// LANRouteDevice is a LAN device let in to a private domain route.
type LANRouteDevice struct {
	ID    int64
	IP    string
	Iface string // its network's interface
}

// LANRouteAccess maps every enabled private domain route that LAN devices may use to those
// devices: all approved, unblocked devices on enabled networks when the route lets every LAN
// in, else the ones picked for it that are approved and unblocked. A route no device may use is
// left out. This is the one answer the Traefik routes, the LAN firewall and the Cloudflare-only
// gate all take, so they never disagree on who gets in.
func (d *DB) LANRouteAccess() (map[string][]LANRouteDevice, error) {
	rows, err := d.Query(`SELECT r.domain, c.id, c.ip, n.iface, n.cidr
		FROM domain_routes r
		JOIN dhcp_clients c ON c.approved = 1 AND c.blocked = 0 AND c.ip <> ''
		JOIN dhcp_networks n ON n.id = c.network_id AND n.enabled = 1
		WHERE r.enabled = 1 AND COALESCE(NULLIF(r.access_mode, ''), 'vpn') = 'vpn'
		  AND (r.lan_all = 1 OR EXISTS (SELECT 1 FROM domain_route_lan_devices p
		                               WHERE p.route_id = r.id AND p.device_id = c.id))
		ORDER BY r.domain, c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]LANRouteDevice{}
	for rows.Next() {
		var domain, cidr string
		var dev LANRouteDevice
		if err := rows.Scan(&domain, &dev.ID, &dev.IP, &dev.Iface, &cidr); err != nil {
			return nil, err
		}
		// Only an IPv4 address inside its own network: a stale or odd one lets nothing in.
		ip, err := netip.ParseAddr(dev.IP)
		subnet, perr := netip.ParsePrefix(cidr)
		if err != nil || perr != nil || !ip.Is4() || !subnet.Contains(ip) {
			continue
		}
		out[domain] = append(out[domain], dev)
	}
	return out, rows.Err()
}

// LANRouteDevices lists each device that may use at least one private domain route, once, in ID
// order so the rules built from it stay the same between applies.
func (d *DB) LANRouteDevices() ([]LANRouteDevice, error) {
	access, err := d.LANRouteAccess()
	if err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	var out []LANRouteDevice
	for _, devs := range access {
		for _, dev := range devs {
			if !seen[dev.ID] {
				seen[dev.ID] = true
				out = append(out, dev)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
