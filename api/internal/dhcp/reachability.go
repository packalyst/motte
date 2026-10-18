package dhcp

import (
	"fmt"
	"net"
	"os"
	"strings"

	"api/internal/database"
)

// ReachabilityTable builds `inet wgadmin_dhcp_net`: a default-deny forward chain exposing each
// managed segment to only the opted-in VPN clients, plus an off-by-default masquerade for
// internet-out. Registered with the firewall's nftables service so it rebuilds on every apply.
type ReachabilityTable struct {
	db *database.DB
}

func NewReachabilityTable(db *database.DB) *ReachabilityTable { return &ReachabilityTable{db: db} }

func (t *ReachabilityTable) Name() string   { return "wgadmin_dhcp_net" }
func (t *ReachabilityTable) Family() string { return "inet" }

// Priority 15: after the VPN ACL (20 builds later; priority here is the apply order used by the
// service, not the nft chain hook priority) — both coexist, they govern disjoint traffic
// (VPN<->VPN vs VPN<->segment).
func (t *ReachabilityTable) Priority() int { return 15 }

func (t *ReachabilityTable) Build() (string, error) {
	svc := &Service{db: t.db}
	nets, err := svc.listNetworks()
	if err != nil {
		return "", err
	}
	// Resolve each network's opted-in VPN client IPs up front, so the renderer stays pure.
	allowed := make(map[int64][]string, len(nets))
	// In "approve" mode the forward gate opens per-device: only approved devices' IPs may be
	// forwarded (reached by VPN / routed out). Pending devices get an address but no forwarding.
	approved := make(map[int64][]string, len(nets))
	for i := range nets {
		ids, _ := svc.listNetworkACL(nets[i].ID)
		for _, id := range ids {
			if ip, err := svc.clientIPByID(id); err == nil {
				allowed[nets[i].ID] = append(allowed[nets[i].ID], ip)
			}
		}
		if nets[i].Mode == "approve" {
			_, cnet, _ := net.ParseCIDR(nets[i].CIDR)
			clients, _ := svc.listClients(nets[i].ID)
			for _, c := range clients {
				ip := net.ParseIP(strings.TrimSpace(c.IP))
				if c.Approved && ip != nil && ip.To4() != nil && cnet != nil && cnet.Contains(ip) {
					approved[nets[i].ID] = append(approved[nets[i].ID], ip.String())
				}
			}
		}
	}
	wan, _ := defaultRouteInterface()
	return renderReachability(nets, allowed, approved, wan), nil
}

// renderReachability builds the nft script (pure: no DB, no host calls) so it can be unit-tested
// and syntax-checked with `nft -c`. Every IP/CIDR/iface is validated before emission.
func renderReachability(nets []Network, allowed map[int64][]string, approved map[int64][]string, wan string) string {
	var fwd strings.Builder
	var nat strings.Builder
	for i := range nets {
		n := &nets[i]
		if !n.Enabled {
			continue
		}
		if _, _, err := net.ParseCIDR(n.CIDR); err != nil {
			continue // defensive: never emit an unvalidated CIDR
		}
		fmt.Fprintf(&fwd, "        # network %s (%s, %s)\n", n.Iface, n.CIDR, n.Mode)

		// What may be forwarded: the whole subnet in "auto" mode, or only approved devices' IPs in
		// "approve" mode (pending devices get an address but are gated here). An approve network
		// with nothing approved yet has no targets, so nothing on it is reachable.
		targets := []string{n.CIDR}
		if n.Mode == "approve" {
			targets = approved[n.ID]
		}

		// Opted-in VPN clients may reach the forwardable hosts.
		for _, ip := range allowed[n.ID] {
			if net.ParseIP(ip) == nil {
				continue
			}
			for _, t := range targets {
				fmt.Fprintf(&fwd, "        ip saddr %s ip daddr %s accept\n", ip, t)
			}
		}

		// Internet-out (off by default): allow forwardable hosts OUT the WAN + masquerade the subnet.
		if n.NATEnabled && validIface(wan) {
			for _, t := range targets {
				fmt.Fprintf(&fwd, "        ip saddr %s oifname %q accept\n", t, wan)
			}
			fmt.Fprintf(&nat, "        ip saddr %s oifname %q masquerade\n", n.CIDR, wan)
		}

		// Default-deny: nothing else reaches the segment, and the segment initiates nothing
		// else (replies ride ct established,related at the top). True sandbox when NAT is off.
		fmt.Fprintf(&fwd, "        ip daddr %s drop\n", n.CIDR)
		fmt.Fprintf(&fwd, "        ip saddr %s drop\n\n", n.CIDR)
	}

	var sb strings.Builder
	sb.WriteString("table inet wgadmin_dhcp_net {\n")
	sb.WriteString("    chain forward {\n")
	sb.WriteString("        type filter hook forward priority 10; policy accept;\n")
	sb.WriteString("        ct state established,related accept\n")
	sb.WriteString(fwd.String())
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
