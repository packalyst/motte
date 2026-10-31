package dhcp

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func scanNetwork(row interface{ Scan(...any) error }) (*Network, error) {
	var n Network
	var nat, enabled int
	if err := row.Scan(&n.ID, &n.Iface, &n.CIDR, &n.GatewayIP, &n.PoolStart, &n.PoolEnd,
		&n.LeaseSecs, &n.Domain, &n.Mode, &nat, &enabled); err != nil {
		return nil, err
	}
	n.NATEnabled = nat == 1
	n.Enabled = enabled == 1
	return &n, nil
}

const networkCols = `id, iface, cidr, gateway_ip, pool_start, pool_end, lease_secs, domain, mode, nat_enabled, enabled`

func (s *Service) listNetworks() ([]Network, error) {
	rows, err := s.db.Query(`SELECT ` + networkCols + ` FROM dhcp_networks ORDER BY iface`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Network
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func (s *Service) getNetwork(id int64) (*Network, error) {
	return scanNetwork(s.db.QueryRow(`SELECT `+networkCols+` FROM dhcp_networks WHERE id = ?`, id))
}

// otherNetworks returns every network except excludeID (0 = none), for overlap validation.
func (s *Service) otherNetworks(excludeID int64) ([]Network, error) {
	all, err := s.listNetworks()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, n := range all {
		if n.ID != excludeID {
			out = append(out, n)
		}
	}
	return out, nil
}

func (s *Service) createNetwork(n *Network) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO dhcp_networks
		(iface, cidr, gateway_ip, pool_start, pool_end, lease_secs, domain, mode, nat_enabled, enabled)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		n.Iface, n.CIDR, n.GatewayIP, n.PoolStart, n.PoolEnd, n.LeaseSecs, n.Domain, n.Mode,
		b2i(n.NATEnabled), b2i(n.Enabled))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Service) updateNetwork(n *Network) error {
	_, err := s.db.Exec(`UPDATE dhcp_networks SET
		cidr=?, gateway_ip=?, pool_start=?, pool_end=?, lease_secs=?, domain=?, mode=?,
		nat_enabled=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		n.CIDR, n.GatewayIP, n.PoolStart, n.PoolEnd, n.LeaseSecs, n.Domain, n.Mode,
		b2i(n.NATEnabled), b2i(n.Enabled), n.ID)
	return err
}

func (s *Service) deleteNetwork(id int64) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_networks WHERE id = ?`, id)
	return err
}

// --- DHCP clients (reservations), keyed by MAC ---

const clientCols = `id, network_id, mac, ip, name, approved, blocked, internet, vpn_ip, COALESCE(last_seen,'')`

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	var c Client
	var approved, blocked, internet int
	if err := row.Scan(&c.ID, &c.NetworkID, &c.MAC, &c.IP, &c.Name, &approved, &blocked, &internet, &c.VPNIP, &c.LastSeen); err != nil {
		return nil, err
	}
	c.Approved, c.Blocked, c.Internet = approved == 1, blocked == 1, internet == 1
	return &c, nil
}

func (s *Service) listClients(networkID int64) ([]Client, error) {
	rows, err := s.db.Query(`SELECT `+clientCols+` FROM dhcp_clients WHERE network_id = ? ORDER BY ip, mac`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Service) getClient(id int64) (*Client, error) {
	return scanClient(s.db.QueryRow(`SELECT `+clientCols+` FROM dhcp_clients WHERE id = ?`, id))
}

// upsertClient records a seen MAC (auto-approved in "auto" mode). name is the hostname the device
// advertised via DHCP; it seeds the display name on first sight and fills a still-empty name later,
// but NEVER overwrites one set by hand (a reservation). It also never downgrades an approval and
// never touches blocked/internet. A new device's internet access starts at its network's default.
func (s *Service) upsertClient(networkID int64, mac, ip, name string, autoApprove bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	name = sanitizeLeaseName(name)
	_, err := s.db.Exec(`INSERT INTO dhcp_clients (network_id, mac, ip, name, approved, last_seen, internet)
		VALUES (?,?,?,?,?,?, COALESCE((SELECT nat_enabled FROM dhcp_networks WHERE id = ?), 0))
		ON CONFLICT(mac) DO UPDATE SET
			ip=excluded.ip,
			last_seen=excluded.last_seen,
			name=CASE WHEN dhcp_clients.name IS NULL OR dhcp_clients.name='' THEN excluded.name ELSE dhcp_clients.name END`,
		networkID, mac, ip, name, b2i(autoApprove), time.Now().UTC().Format(time.RFC3339), networkID)
	return err
}

func (s *Service) setClientApproved(id int64, approved bool) error {
	_, err := s.db.Exec(`UPDATE dhcp_clients SET approved=? WHERE id=?`, b2i(approved), id)
	return err
}

// setClientBlocked blocks or unblocks a device. Blocking also revokes its approval; unblocking
// leaves it pending in "approve" mode (approve=false) or approved again in "auto" mode.
func (s *Service) setClientBlocked(id int64, blocked, approved bool) error {
	_, err := s.db.Exec(`UPDATE dhcp_clients SET blocked=?, approved=? WHERE id=?`, b2i(blocked), b2i(approved), id)
	return err
}

func (s *Service) setClientInternet(id int64, on bool) error {
	_, err := s.db.Exec(`UPDATE dhcp_clients SET internet=? WHERE id=?`, b2i(on), id)
	return err
}

func (s *Service) setClientReservation(id int64, ip, name string) error {
	_, err := s.db.Exec(`UPDATE dhcp_clients SET ip=?, name=? WHERE id=?`, ip, name, id)
	return err
}

func (s *Service) deleteClient(id int64) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_clients WHERE id = ?`, id)
	return err
}

// dnsmasqHosts returns what a network's dnsmasq config pins per MAC: reservations for approved
// devices with an IP (a stable address — the firewall gate keys on it), and the blocked MACs that
// must get no address at all.
func (s *Service) dnsmasqHosts(networkID int64) (reservations []Client, blocked []string, err error) {
	all, err := s.listClients(networkID)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range all {
		switch {
		case !validMAC(c.MAC):
		case c.Blocked:
			blocked = append(blocked, strings.ToLower(c.MAC))
		case c.Approved && c.IP != "":
			reservations = append(reservations, c)
		}
	}
	return reservations, blocked, nil
}

// --- per-device reachability ACL (which VPN clients may reach a LAN device) ---

func (s *Service) listDeviceACL(deviceID int64) ([]Grant, error) {
	rows, err := s.db.Query(`SELECT source_client_id, bidirectional FROM dhcp_client_acl WHERE device_id = ?`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Grant{}
	for rows.Next() {
		var g Grant
		var both int
		if err := rows.Scan(&g.ClientID, &both); err != nil {
			return nil, err
		}
		g.Bidirectional = both == 1
		out = append(out, g)
	}
	return out, rows.Err()
}

// setDeviceACL grants a VPN client access to a device, or changes the grant's direction.
func (s *Service) setDeviceACL(deviceID, clientID int64, bidirectional bool) error {
	_, err := s.db.Exec(`INSERT INTO dhcp_client_acl (device_id, source_client_id, bidirectional) VALUES (?,?,?)
		ON CONFLICT(device_id, source_client_id) DO UPDATE SET bidirectional = excluded.bidirectional`,
		deviceID, clientID, b2i(bidirectional))
	return err
}

func (s *Service) removeDeviceACL(deviceID, clientID int64) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_client_acl WHERE device_id=? AND source_client_id=?`, deviceID, clientID)
	return err
}

// vpnGrant is one granted VPN client as the firewall and the Headscale policy need it.
type vpnGrant struct {
	ClientID  int64
	IP        string // the VPN client's address
	Headscale bool   // a Headscale node (its access also goes in the Headscale policy)
	Both      bool   // the device may reach it too
}

// networkGrants maps each device of a network to the VPN clients allowed to reach it.
func (s *Service) networkGrants(networkID int64) (map[int64][]vpnGrant, error) {
	rows, err := s.db.Query(`SELECT a.device_id, v.id, v.ip, v.type, a.bidirectional FROM dhcp_client_acl a
		JOIN dhcp_clients d ON d.id = a.device_id
		JOIN vpn_clients v ON v.id = a.source_client_id
		WHERE d.network_id = ?`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]vpnGrant{}
	for rows.Next() {
		var id int64
		var g vpnGrant
		var typ string
		var both int
		if err := rows.Scan(&id, &g.ClientID, &g.IP, &typ, &both); err != nil {
			return nil, err
		}
		g.Headscale, g.Both = typ == "headscale", both == 1
		out[id] = append(out[id], g)
	}
	return out, rows.Err()
}

// clientIPByID resolves a VPN client's IP for building the forward-chain allow rules.
func (s *Service) clientIPByID(id int64) (string, error) {
	var ip string
	err := s.db.QueryRow(`SELECT ip FROM vpn_clients WHERE id = ?`, id).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("vpn client %d not found", id)
	}
	return ip, err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
