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
	wan, _ := defaultRouteInterface()

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
		fmt.Fprintf(&fwd, "        # network %s (%s)\n", n.Iface, n.CIDR)

		// Opted-in VPN clients may reach the segment.
		ids, _ := svc.listNetworkACL(n.ID)
		for _, id := range ids {
			ip, err := svc.clientIPByID(id)
			if err != nil || net.ParseIP(ip) == nil {
				continue
			}
			fmt.Fprintf(&fwd, "        ip saddr %s ip daddr %s accept\n", ip, n.CIDR)
		}

		// Internet-out (off by default): allow the segment OUT the WAN + masquerade it.
		if n.NATEnabled && validIface(wan) {
			fmt.Fprintf(&fwd, "        ip saddr %s oifname %q accept\n", n.CIDR, wan)
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
	return sb.String(), nil
}

// ensureIPForward enables IPv4 forwarding (needed to route between wg0 and the segment). Writes
// the shared-netns proc file directly — no extra binary, and it's the host's netns since the api
// is host-networked. Best-effort: forwarding may already be on from the WireGuard setup.
func ensureIPForward() {
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
}
