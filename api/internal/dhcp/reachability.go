package dhcp

import (
	"fmt"
	"net"
	"os"
	"strings"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/nftables"
)

// rfc1918Ranges are the private IPv4 blocks a managed segment must never reach via internet-out.
// Combined at build time with the live WireGuard/Headscale ranges to form the private_ranges set,
// so the segment's NAT path reaches the PUBLIC internet only — never other internal/VPN networks.
var rfc1918Ranges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// privateReachRanges returns the destinations the segment must not reach when internet-out is on:
// RFC1918 plus the live VPN/overlay ranges (same env the VPN ACL reads, so it tracks the real
// deployment instead of hardcoding). Invalid/empty env values are skipped.
func privateReachRanges() []string {
	ranges := append([]string{}, rfc1918Ranges...)
	for _, r := range []string{
		helper.GetEnvOptional("WG_IP_RANGE", ""),
		helper.GetEnvOptional("HEADSCALE_IP_RANGE", ""),
	} {
		if nftables.ValidateIPv4OrCIDR(r) {
			ranges = append(ranges, r)
		}
	}
	return ranges
}

// ReachabilityTable builds `inet motte_dhcp_net`: a default-deny forward chain exposing each
// managed segment to only the opted-in VPN clients, plus an off-by-default masquerade for
// internet-out. Registered with the firewall's nftables service so it rebuilds on every apply.
type ReachabilityTable struct {
	db *database.DB
}

func NewReachabilityTable(db *database.DB) *ReachabilityTable { return &ReachabilityTable{db: db} }

func (t *ReachabilityTable) Name() string   { return "motte_dhcp_net" }
func (t *ReachabilityTable) Family() string { return "inet" }

// Priority 15: after the VPN ACL (20 builds later; priority here is the apply order used by the
// service, not the nft chain hook priority) — both coexist, they govern disjoint traffic
// (VPN<->VPN vs VPN<->segment).
func (t *ReachabilityTable) Priority() int { return 15 }

// devicePolicy is one approved, unblocked LAN device's forwarding policy.
type devicePolicy struct {
	IP       string   // its IPv4 address inside the network (the firewall gate keys on it)
	Allowed  []string // VPN client IPs that may reach it, and it them
	Internet bool     // may route out the WAN
}

// netPolicy is a network's forwarding policy, resolved from the DB before rendering so the
// renderer stays pure (no DB, no host calls) and testable.
type netPolicy struct {
	Devices []devicePolicy
	Blocked []string // MACs dropped outright, whatever IP they use
}

func (t *ReachabilityTable) Build() (string, error) {
	svc := &Service{db: t.db}
	nets, err := svc.listNetworks()
	if err != nil {
		return "", err
	}
	pol := make(map[int64]netPolicy, len(nets))
	for i := range nets {
		if p, err := svc.networkPolicy(&nets[i]); err == nil {
			pol[nets[i].ID] = p
		} else {
			return "", err // fail the build rather than apply a partial (more open) policy
		}
	}
	wan, _ := defaultRouteInterface()
	return renderReachability(nets, pol, wan, privateReachRanges()), nil
}

// networkPolicy resolves a network's devices into forwarding policy. Only approved, unblocked
// devices with a valid address inside the subnet are forwardable ("auto" mode approves on sight);
// pending ones get an address but nothing else. Blocked devices are listed by MAC.
func (s *Service) networkPolicy(n *Network) (netPolicy, error) {
	var p netPolicy
	clients, err := s.listClients(n.ID)
	if err != nil {
		return p, err
	}
	acl, err := s.networkACLIPs(n.ID)
	if err != nil {
		return p, err
	}
	_, cnet, err := net.ParseCIDR(n.CIDR)
	if err != nil {
		return p, nil // an invalid network renders nothing (renderReachability skips it too)
	}
	for _, c := range clients {
		if c.Blocked {
			p.Blocked = append(p.Blocked, strings.ToLower(c.MAC))
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(c.IP))
		if !c.Approved || ip == nil || ip.To4() == nil || !cnet.Contains(ip) {
			continue
		}
		p.Devices = append(p.Devices, devicePolicy{IP: ip.String(), Allowed: acl[c.ID], Internet: c.Internet})
	}
	return p, nil
}

// hasInternet reports whether any device in the policy may route out the WAN.
func (p netPolicy) hasInternet() bool {
	for _, d := range p.Devices {
		if d.Internet {
			return true
		}
	}
	return false
}

// renderReachability builds the nft script (pure: no DB, no host calls) so it can be unit-tested
// and syntax-checked with `nft -c`. Every IP/CIDR/MAC/iface is validated before emission.
func renderReachability(nets []Network, pol map[int64]netPolicy, wan string, privateRanges []string) string {
	var blk, fwd, in, nat strings.Builder
	for i := range nets {
		n := &nets[i]
		if !n.Enabled || !validIface(n.Iface) {
			continue
		}
		if _, _, err := net.ParseCIDR(n.CIDR); err != nil {
			continue // defensive: never emit an unvalidated CIDR
		}
		p := pol[n.ID]
		fmt.Fprintf(&fwd, "        # network %s (%s, %s)\n", n.Iface, n.CIDR, n.Mode)

		// Blocked devices: dropped by MAC — routed traffic and traffic to the box itself (DNS, the
		// panel) — so a static IP can't get around it, and a later device that inherits the old
		// address isn't caught by it. These go above the established/related accept, so blocking
		// also cuts connections that are already open.
		for _, mac := range p.Blocked {
			if !validMAC(mac) {
				continue
			}
			rule := fmt.Sprintf("iifname %q ether saddr %s drop", n.Iface, mac)
			fmt.Fprintf(&blk, "        %s\n", rule)
			fmt.Fprintf(&in, "        %s\n", rule)
		}

		// Per-device access: each granted VPN client and that one device reach each OTHER — the grant
		// is symmetric, like the VPN ACL. Emitted ABOVE the private-range drop below so a granted
		// client inside a VPN range stays reachable.
		for _, d := range p.Devices {
			if net.ParseIP(d.IP) == nil {
				continue
			}
			for _, ip := range d.Allowed {
				if net.ParseIP(ip) == nil {
					continue
				}
				for _, rule := range nftables.BidirectionalAccept(ip, d.IP) {
					fmt.Fprintf(&fwd, "        %s\n", rule)
				}
			}
		}

		// Internet-out, per device: only devices with it on reach the PUBLIC internet; the segment is
		// masqueraded once any of them is.
		if p.hasInternet() && validIface(wan) {
			// Leak guard: refuse the segment → private/VPN ranges BEFORE the WAN accept, so a
			// destination that merely routes via the WAN NIC (e.g. a datacenter 10.0.0.0/8) is
			// dropped instead of silently masqueraded out. Its own subnet is excluded (local, and
			// never forwarded anyway); the access pairs above already cleared any granted VPN client.
			if len(privateRanges) > 0 {
				fmt.Fprintf(&fwd, "        ip saddr %s ip daddr @private_ranges ip daddr != %s drop\n", n.CIDR, n.CIDR)
			}
			for _, d := range p.Devices {
				if d.Internet && net.ParseIP(d.IP) != nil {
					fmt.Fprintf(&fwd, "        ip saddr %s oifname %q accept\n", d.IP, wan)
				}
			}
			fmt.Fprintf(&nat, "        ip saddr %s oifname %q masquerade\n", n.CIDR, wan)
		}

		// Default-deny: nothing else reaches the segment, and the segment initiates nothing
		// else (replies ride ct established,related at the top). True sandbox when NAT is off.
		fmt.Fprintf(&fwd, "        ip daddr %s drop\n", n.CIDR)
		fmt.Fprintf(&fwd, "        ip saddr %s drop\n\n", n.CIDR)
	}

	var sb strings.Builder
	sb.WriteString("table inet motte_dhcp_net {\n")
	// private_ranges: destinations a segment must never reach via internet-out (RFC1918 + the live
	// VPN/overlay ranges). Interval+auto-merge so overlapping CIDRs collapse cleanly.
	sb.WriteString(nftables.BuildSet("private_ranges", "ipv4_addr", []string{"interval", "auto-merge"}, privateRanges))
	sb.WriteString("    chain forward {\n")
	sb.WriteString("        type filter hook forward priority 10; policy accept;\n")
	sb.WriteString(blk.String())
	sb.WriteString("        ct state established,related accept\n")
	sb.WriteString(fwd.String())
	sb.WriteString("    }\n")
	// Blocked devices must not reach the box itself either. A drop is final across base chains, so
	// this holds whatever the host firewall's input chain accepts.
	sb.WriteString("    chain input {\n")
	sb.WriteString("        type filter hook input priority 10; policy accept;\n")
	sb.WriteString(in.String())
	sb.WriteString("    }\n")
	sb.WriteString("    chain postrouting {\n")
	sb.WriteString("        type nat hook postrouting priority 100; policy accept;\n")
	sb.WriteString(nat.String())
	sb.WriteString("    }\n")
	sb.WriteString("}\n")
	return sb.String()
}

// ensureIPForward enables IPv4 forwarding (needed to route between wg0 and the segment). Writes
// the shared-netns proc file directly — no extra binary, and it's the host's netns since the api
// is host-networked. Best-effort: forwarding may already be on from the WireGuard setup.
func ensureIPForward() {
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
}
