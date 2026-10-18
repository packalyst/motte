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

func (s *Service) getNetworkByIface(iface string) (*Network, error) {
	return scanNetwork(s.db.QueryRow(`SELECT `+networkCols+` FROM dhcp_networks WHERE iface = ?`, iface))
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

func (s *Service) listClients(networkID int64) ([]Client, error) {
	rows, err := s.db.Query(`SELECT id, network_id, mac, ip, name, approved,
		COALESCE(last_seen,'') FROM dhcp_clients WHERE network_id = ? ORDER BY ip, mac`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var approved int
		if err := rows.Scan(&c.ID, &c.NetworkID, &c.MAC, &c.IP, &c.Name, &approved, &c.LastSeen); err != nil {
			return nil, err
		}
		c.Approved = approved == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) getClient(id int64) (*Client, error) {
	var c Client
	var approved int
	err := s.db.QueryRow(`SELECT id, network_id, mac, ip, name, approved, COALESCE(last_seen,'')
		FROM dhcp_clients WHERE id = ?`, id).Scan(&c.ID, &c.NetworkID, &c.MAC, &c.IP, &c.Name, &approved, &c.LastSeen)
	if err != nil {
		return nil, err
	}
	c.Approved = approved == 1
	return &c, nil
}

// upsertClient records a seen MAC (auto-approved in "auto" mode). name is the hostname the device
// advertised via DHCP; it seeds the display name on first sight and fills a still-empty name later,
// but NEVER overwrites one set by hand (a reservation). It also never downgrades an approval.
func (s *Service) upsertClient(networkID int64, mac, ip, name string, autoApprove bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	name = sanitizeLeaseName(name)
	_, err := s.db.Exec(`INSERT INTO dhcp_clients (network_id, mac, ip, name, approved, last_seen)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(mac) DO UPDATE SET
			ip=excluded.ip,
			last_seen=excluded.last_seen,
			name=CASE WHEN dhcp_clients.name IS NULL OR dhcp_clients.name='' THEN excluded.name ELSE dhcp_clients.name END`,
		networkID, mac, ip, name, b2i(autoApprove), time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *Service) setClientApproved(id int64, approved bool) error {
	_, err := s.db.Exec(`UPDATE dhcp_clients SET approved=? WHERE id=?`, b2i(approved), id)
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

// approvedReservations returns the MAC→(ip,name) reservations dnsmasq should honour for a
// network: approved clients that have a pinned IP. In "auto" mode everything is approved.
func (s *Service) approvedReservations(networkID int64) ([]Client, error) {
	all, err := s.listClients(networkID)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, c := range all {
		if c.Approved && c.IP != "" && validMAC(c.MAC) {
			out = append(out, c)
		}
	}
	return out, nil
}

// --- per-network reachability ACL (which VPN clients may reach the segment) ---

func (s *Service) listNetworkACL(networkID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT source_client_id FROM dhcp_network_acl WHERE network_id = ?`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Service) addNetworkACL(networkID, clientID int64) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO dhcp_network_acl (network_id, source_client_id)
		VALUES (?,?)`, networkID, clientID)
	return err
}

func (s *Service) removeNetworkACL(networkID, clientID int64) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_network_acl WHERE network_id=? AND source_client_id=?`,
		networkID, clientID)
	return err
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
