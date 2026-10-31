// Package dhcp lets the panel act as the gateway for isolated private LAN segments behind it:
// it manages the segment's interface address (via a panel-owned netplan drop-in), runs a
// DHCP-only dnsmasq for it, surfaces leased devices as a new entity, and gates VPN reachability
// through the nftables forward chain under the same default-deny model as virtual IPs.
//
// It is strictly for real L2 segments the box gateways (a NIC/VLAN/bridge) — never for VPN
// peers, which get their address from their WireGuard config (wg0 is L3, no DHCP).
package dhcp

// Network is a panel-managed private LAN segment.
type Network struct {
	ID         int64  `json:"id"`
	Iface      string `json:"iface"`       // the L2 NIC the box gateways (e.g. ens19)
	CIDR       string `json:"cidr"`        // e.g. 10.20.20.0/24
	GatewayIP  string `json:"gateway_ip"`  // the box's address on the segment (DHCP option 3)
	PoolStart  string `json:"pool_start"`  // first leasable address
	PoolEnd    string `json:"pool_end"`    // last leasable address
	LeaseSecs  int    `json:"lease_secs"`  // DHCP lease duration
	Domain     string `json:"domain"`      // DNS suffix for leased names (e.g. lan)
	Mode       string `json:"mode"`        // "auto" | "approve"
	NATEnabled bool   `json:"nat_enabled"` // internet-out masquerade (off by default)
	Enabled    bool   `json:"enabled"`
}

// Client is a DHCP lease/reservation, keyed by MAC.
type Client struct {
	ID        int64  `json:"id"`
	NetworkID int64  `json:"network_id"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Name      string `json:"name"`
	Approved  bool   `json:"approved"`
	Blocked   bool   `json:"blocked"`  // no address (dnsmasq ignore) and dropped by MAC in the firewall
	Internet  bool   `json:"internet"` // may route out the WAN; seeded from the network's nat_enabled
	// VPNIP is the device's address inside the WireGuard range, given on its first grant: VPN
	// clients reach it there and the box swaps it for IP. Empty until then.
	VPNIP    string `json:"vpn_ip,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
	// Online and LeaseExpires are derived at read time from the live dnsmasq lease file, not
	// stored. LeaseExpires is the active lease's end (unix seconds); 0 = none or never expires.
	Online       bool  `json:"online"`
	LeaseExpires int64 `json:"lease_expires,omitempty"`
}

// Grant lets a VPN client reach a LAN device; Bidirectional lets the device reach it too.
type Grant struct {
	ClientID      int64 `json:"id"`
	Bidirectional bool  `json:"bidirectional"`
}
