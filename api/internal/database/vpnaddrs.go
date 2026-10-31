package database

// VPN address owners. Three things hold addresses inside the WireGuard range: VPN clients, virtual
// IPs (extra /32s routed to a peer) and LAN devices (their VPN address, swapped to the real one on
// the box). Every allocator reserves all three, so none can be handed another's address.
const (
	VPNAddrClient  = "client"
	VPNAddrVirtual = "virtual"
	VPNAddrLAN     = "lan"
)

// VPNAddressOwners maps every address in use to what holds it. Should two ever share one, a client
// or virtual IP wins over a LAN device, so the LAN device's address swap is the one left out,
// never the peer's route.
func (d *DB) VPNAddressOwners() (map[string]string, error) {
	rows, err := d.Query(`SELECT vpn_ip, '` + VPNAddrLAN + `' FROM dhcp_clients WHERE vpn_ip <> ''
		UNION ALL SELECT ip, '` + VPNAddrVirtual + `' FROM vpn_virtual_ips
		UNION ALL SELECT ip, '` + VPNAddrClient + `' FROM vpn_clients WHERE ip <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	owners := map[string]string{}
	for rows.Next() {
		var ip, owner string
		if err := rows.Scan(&ip, &owner); err != nil {
			return nil, err
		}
		if owners[ip] == "" || owners[ip] == VPNAddrLAN {
			owners[ip] = owner
		}
	}
	return owners, rows.Err()
}
