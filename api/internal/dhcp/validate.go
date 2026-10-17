package dhcp

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"api/internal/helper"
)

// validMAC/validIface constrain values before they're ever written into a dnsmasq/netplan file
// or an nft rule. A MAC is six colon-separated hex octets; an interface name is the restrictive
// Linux set (letters, digits, and . _ - @), length-bounded, no path/space/shell metacharacters.
var (
	hexOctet = "[0-9a-fA-F]{2}"
)

func validMAC(s string) bool {
	_, err := net.ParseMAC(strings.TrimSpace(s))
	return err == nil && strings.Count(s, ":") == 5 // require EUI-48, colon form
}

func validIface(s string) bool {
	if s == "" || len(s) > 15 { // IFNAMSIZ-1
		return false
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' || r == '@'
		if !ok {
			return false
		}
	}
	return true
}

// validateNetwork enforces every "must be extremely secure" guard before a network is accepted:
// a real non-WAN interface, a private subnet, a gateway inside it, a sane pool inside it, and no
// overlap with the WireGuard/Headscale ranges or any OTHER managed network. others is every
// existing network except the one being saved (pass its ID in excludeID, 0 for a create).
func validateNetwork(n *Network, others []Network) error {
	n.Iface = strings.TrimSpace(n.Iface)
	if !validIface(n.Iface) {
		return fmt.Errorf("invalid interface name")
	}
	if err := requireNonWANInterface(n.Iface); err != nil {
		return err
	}
	return validateAddressing(n, others)
}

// validateAddressing checks the subnet/gateway/pool/lease/mode/domain and overlap rules and
// normalizes the fields. Split out from the interface/WAN check so it's deterministically
// testable without a live host.
func validateAddressing(n *Network, others []Network) error {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(n.CIDR))
	if err != nil {
		return fmt.Errorf("invalid subnet CIDR (e.g. 10.20.20.0/24)")
	}
	n.CIDR = ipnet.String()
	if ones, _ := ipnet.Mask.Size(); ones > 30 {
		return fmt.Errorf("subnet is too small for a DHCP pool (use /30 or larger)")
	}
	if !isPrivateNet(ipnet) {
		return fmt.Errorf("managed network must use a private range (RFC1918: 10/8, 172.16/12, 192.168/16)")
	}

	gw := net.ParseIP(strings.TrimSpace(n.GatewayIP))
	if gw == nil || gw.To4() == nil || !ipnet.Contains(gw) {
		return fmt.Errorf("gateway IP must be an IPv4 address inside the subnet")
	}
	n.GatewayIP = gw.String()

	start := net.ParseIP(strings.TrimSpace(n.PoolStart))
	end := net.ParseIP(strings.TrimSpace(n.PoolEnd))
	if start == nil || start.To4() == nil || !ipnet.Contains(start) {
		return fmt.Errorf("pool start must be an IPv4 address inside the subnet")
	}
	if end == nil || end.To4() == nil || !ipnet.Contains(end) {
		return fmt.Errorf("pool end must be an IPv4 address inside the subnet")
	}
	if ip4Less(end.To4(), start.To4()) {
		return fmt.Errorf("pool end must not be before pool start")
	}
	if ipEqual(start, gw) || ipEqual(end, gw) || ipInRange(gw, start, end) {
		return fmt.Errorf("DHCP pool must not include the gateway IP")
	}
	n.PoolStart, n.PoolEnd = start.String(), end.String()

	if n.LeaseSecs < 120 || n.LeaseSecs > 30*24*3600 {
		return fmt.Errorf("lease time must be between 2 minutes and 30 days")
	}
	if n.Mode != "auto" && n.Mode != "approve" {
		return fmt.Errorf("mode must be auto or approve")
	}
	n.Domain = strings.TrimSpace(n.Domain)
	if n.Domain == "" {
		n.Domain = "lan"
	}
	if !validDomainLabel(n.Domain) {
		return fmt.Errorf("domain must be a simple DNS label (letters, digits, hyphens, dots)")
	}

	// No overlap with the VPN ranges — a managed LAN sharing addresses with the VPN would make
	// the ACL/routing ambiguous.
	for _, env := range []string{"WG_IP_RANGE", "HEADSCALE_IP_RANGE"} {
		if r := strings.TrimSpace(helper.GetEnvOptional(env, "")); r != "" {
			if _, vpnNet, e := net.ParseCIDR(r); e == nil && netsOverlap(ipnet, vpnNet) {
				return fmt.Errorf("subnet overlaps the VPN range %s", r)
			}
		}
	}
	// No overlap with another managed network, and no reuse of its interface.
	for _, o := range others {
		if o.Iface == n.Iface {
			return fmt.Errorf("interface %s is already managed by another network", n.Iface)
		}
		if _, oNet, e := net.ParseCIDR(o.CIDR); e == nil && netsOverlap(ipnet, oNet) {
			return fmt.Errorf("subnet overlaps managed network %s", o.CIDR)
		}
	}
	return nil
}

// SubnetSuggestion is a ready-to-use safe /24 the UI offers in a dropdown, with sensible gateway
// and pool defaults derived from it.
type SubnetSuggestion struct {
	CIDR      string `json:"cidr"`
	GatewayIP string `json:"gateway_ip"`
	PoolStart string `json:"pool_start"`
	PoolEnd   string `json:"pool_end"`
}

// subnetPool generates the candidate CIDRs algorithmically across 10.0.0.0/8 as 10.N.N.0/24 for
// N = 20,30,…,250 — a memorable 10.20.20 / 10.30.30 / 10.40.40 … sequence with no hand-maintained
// list that effectively never runs out.
func subnetPool() []string {
	pool := make([]string, 0, 24)
	for n := 20; n <= 250; n += 10 {
		pool = append(pool, fmt.Sprintf("10.%d.%d.0/24", n, n))
	}
	return pool
}

// suggestSubnets returns up to max candidate /24s that are safe to use RIGHT NOW: for each
// pool entry it derives gateway .1 / pool .50–.200 and only offers it if it passes the SAME
// validateAddressing a save runs — so overlap with the VPN ranges (WG_IP_RANGE /
// HEADSCALE_IP_RANGE) or an existing managed network, a non-private range, etc. are impossible
// by construction. The validator is the single source of truth for "safe"; this just proposes.
func suggestSubnets(others []Network, max int) []SubnetSuggestion {
	out := []SubnetSuggestion{}
	for _, c := range subnetPool() {
		_, cnet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		b := cnet.IP.To4()
		if b == nil {
			continue
		}
		s := SubnetSuggestion{
			CIDR:      cnet.String(),
			GatewayIP: fmt.Sprintf("%d.%d.%d.1", b[0], b[1], b[2]),
			PoolStart: fmt.Sprintf("%d.%d.%d.50", b[0], b[1], b[2]),
			PoolEnd:   fmt.Sprintf("%d.%d.%d.200", b[0], b[1], b[2]),
		}
		// Sentinel iface so the iface-reuse check in validateAddressing can't false-match (we're
		// probing addressing only — the real interface is chosen separately in the form).
		probe := &Network{Iface: "\x00probe", CIDR: s.CIDR, GatewayIP: s.GatewayIP, PoolStart: s.PoolStart,
			PoolEnd: s.PoolEnd, LeaseSecs: 43200, Domain: "lan", Mode: "approve"}
		if validateAddressing(probe, others) != nil {
			continue // overlaps a VPN/existing range, or the derived pool doesn't fit — skip it
		}
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	return out
}

// requireNonWANInterface refuses the interface that carries the default route. Running DHCP /
// reassigning the address there would hijack the box's own uplink and could lock the operator
// out — the single most important guard in this feature.
func requireNonWANInterface(iface string) error {
	wan, err := defaultRouteInterface()
	if err != nil {
		// Fail closed: if we can't determine the WAN, don't risk managing the wrong NIC.
		return fmt.Errorf("could not determine the WAN interface (refusing for safety): %v", err)
	}
	if iface == wan {
		return fmt.Errorf("refusing to manage %s — it carries the default route (WAN); pick an isolated internal interface", iface)
	}
	return nil
}

// defaultRouteInterface returns the interface of the IPv4 default route via `ip route`.
func defaultRouteInterface() (string, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "dev" {
				return f[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("no default route found")
}

func isPrivateNet(n *net.IPNet) bool {
	ip := n.IP.To4()
	if ip == nil {
		return false
	}
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168)
}

func netsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func validDomainLabel(s string) bool {
	if len(s) > 63 {
		return false
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.'
		if !ok {
			return false
		}
	}
	return true
}

func ipEqual(a, b net.IP) bool { return a.Equal(b) }

func ip4Less(a, b net.IP) bool {
	a, b = a.To4(), b.To4()
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func ipInRange(ip, start, end net.IP) bool {
	ip, start, end = ip.To4(), start.To4(), end.To4()
	if ip == nil || start == nil || end == nil {
		return false
	}
	return !ip4Less(ip, start) && !ip4Less(end, ip)
}
