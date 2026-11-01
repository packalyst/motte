package dhcp

import (
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/nftables"
)

// privateReachRanges returns the destinations the segment must not reach when internet-out is on:
// every non-public block (helper.NonPublicRanges: LANs, the overlay, link-local and the cloud
// metadata address, loopback, multicast, reserved) plus the live VPN/overlay ranges (same env the VPN ACL reads, so it tracks the real
// deployment instead of hardcoding). They form the private_ranges set, so the segment's NAT path
// reaches the PUBLIC internet only — never other internal/VPN networks. Invalid/empty env values
// are skipped.
func privateReachRanges() []string {
	ranges := helper.NonPublicRanges()
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

	// What each device (by MAC) may do, as last applied and as just built: a device that lost any
	// of it has its open connections cut once the new rules are in (ConntrackFlushTargets). The
	// same for the dedicated addresses: one that just became dedicated has every connection to
	// and from it cut.
	mu               sync.Mutex
	applied          map[string]deviceAccess
	built            map[string]deviceAccess
	appliedDedicated []string
	builtDedicated   []string
}

func NewReachabilityTable(db *database.DB) *ReachabilityTable { return &ReachabilityTable{db: db} }

// The firewall service cuts open connections through this once the new rules are in.
var _ nftables.ConntrackFlusher = (*ReachabilityTable)(nil)

func (t *ReachabilityTable) Name() string   { return "motte_dhcp_net" }
func (t *ReachabilityTable) Family() string { return "inet" }

// Priority 15: after the VPN ACL (20 builds later; priority here is the apply order used by the
// service, not the nft chain hook priority) — both coexist, they govern disjoint traffic
// (VPN<->VPN vs VPN<->segment).
func (t *ReachabilityTable) Priority() int { return 15 }

// devicePolicy is one approved, unblocked LAN device's forwarding policy.
type devicePolicy struct {
	IP       string     // its IPv4 address inside the network
	MAC      string     // its MAC: the gate keys on IP + MAC, so copying an approved device's IP isn't enough
	VPNIP    string     // its VPN address, swapped for IP on the box; empty when it has no usable one
	Allowed  []vpnGrant // VPN clients that may reach it (and, Both, it them)
	Internet bool       // may route out the WAN
	Egress   string     // the internet address it leaves from; "" = the server's main address
	Out      outPorts   // what it may reach on the internet (services.go)
	Routes   []int      // TCP ports of the enabled domain routes to its VPN address (Traefik's way in)
}

// internetVia reports whether the device goes out to the internet, and the address it leaves
// from ("" = masqueraded to the main address). A set but invalid address keeps it in: it never
// falls back to the main address.
func (d devicePolicy) internetVia() (string, bool) {
	if !d.Internet {
		return "", false
	}
	if d.Egress == "" {
		return "", true
	}
	ip := dedicatedIP(d.Egress)
	return ip, ip != ""
}

// routeOrigin is where Traefik's traffic enters the host (helper.TraefikOrigin): domain routes to
// LAN devices are let in from exactly this interface and address, nothing else. Zero when it
// can't be resolved, and then no route is let in at all.
type routeOrigin struct {
	Iface string
	IP    string
}

// netPolicy is a network's forwarding policy, resolved from the DB before rendering so the
// renderer stays pure (no DB, no host calls) and testable.
type netPolicy struct {
	Devices []devicePolicy
	Blocked []string // MACs dropped outright, whatever IP they use
	// Dedicated lists every extra internet address the network or one of its devices names: no
	// connection may come in to them, whether or not a device is using one right now.
	Dedicated []string
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
	keepServerAddressesOpen(pol)
	wan, _ := defaultRouteInterface()
	origin := traefikOrigin(pol)
	t.mu.Lock()
	t.built = accessOf(nets, pol, wan, origin)
	t.builtDedicated = dedicatedAddrs(pol)
	t.mu.Unlock()
	return renderReachability(nets, pol, wan, privateReachRanges(), origin), nil
}

// keepServerAddressesOpen takes the server's own addresses out of every Dedicated list: the panel
// address (SERVER_IP) and the address the server sends from right now. A dedicated address that
// later became one of them (the host's addresses changed) is then simply not closed, instead of
// cutting the panel, the VPN and SSH off. The host is only read when an address is dedicated.
func keepServerAddressesOpen(pol map[int64]netPolicy) {
	open := map[string]bool{}
	for id, p := range pol {
		if len(p.Dedicated) == 0 {
			continue
		}
		if len(open) == 0 {
			open[helper.GetEnvOptional("SERVER_IP", "")] = true
			if e, err := loadEgressAddrs(); err == nil {
				open[e.Main] = true
			}
		}
		kept := p.Dedicated[:0]
		for _, a := range p.Dedicated {
			if open[a] {
				log.Printf("dhcp: %s is the server's own address now; it is not closed as an internet address", a)
				continue
			}
			kept = append(kept, a)
		}
		p.Dedicated = kept
		pol[id] = p
	}
}

// deviceAccess is what one device may do, as the rules render it: its addresses, and each path
// in or out (a granted VPN client, the way back to it, a Traefik route port, the internet).
type deviceAccess struct {
	IPs   []string
	Paths map[string]bool
}

// accessOf lists, per device MAC, what the rules let it do (the same conditions the renderer uses).
func accessOf(nets []Network, pol map[int64]netPolicy, wan string, origin routeOrigin) map[string]deviceAccess {
	out := map[string]deviceAccess{}
	routesOpen := validIface(origin.Iface) && net.ParseIP(origin.IP).To4() != nil
	for i := range nets {
		if !nets[i].enforced() {
			continue
		}
		for _, d := range pol[nets[i].ID].Devices {
			if net.ParseIP(d.IP) == nil || !validMAC(d.MAC) {
				continue
			}
			a := deviceAccess{IPs: []string{d.IP}, Paths: map[string]bool{"ip " + d.IP: true}}
			vpn := net.ParseIP(d.VPNIP).To4() != nil
			if vpn {
				a.IPs = append(a.IPs, d.VPNIP)
				a.Paths["vpn "+d.VPNIP] = true
			}
			for _, g := range d.Allowed {
				if net.ParseIP(g.IP) == nil {
					continue
				}
				a.Paths["from "+g.IP] = true
				if g.Both {
					a.Paths["to "+g.IP] = true
				}
			}
			if vpn && routesOpen {
				for _, p := range d.Routes {
					a.Paths["route "+strconv.Itoa(p)] = true
				}
			}
			if via, ok := d.internetVia(); ok && d.Out.any() && validIface(wan) {
				a.Paths["internet "+via] = true // a new address cuts the connections on the old one
				for _, p := range d.Out.paths() {
					a.Paths[p] = true // so does a service taken away
				}
			}
			out[d.MAC] = a
		}
	}
	return out
}

// lostAccess returns the addresses of every device that could do something before that it no
// longer can (or is gone), so their open connections can be cut.
func lostAccess(before, after map[string]deviceAccess) []string {
	var ips []string
	for mac, b := range before {
		a, ok := after[mac]
		for path := range b.Paths {
			if !ok || !a.Paths[path] {
				ips = append(ips, b.IPs...)
				break
			}
		}
	}
	return ips
}

// ConntrackFlushTargets runs once the rules just built are applied: it returns the addresses of
// the devices that lost access, so the connections they had open are cut too instead of riding
// the established-connection accept until they go idle, and every address that just became
// dedicated, so nothing that was connected to it before stays connected. The first apply after
// start cuts no device (there is nothing to compare with) but every dedicated address: what
// is legitimately on one is the devices' own connections, which start from the devices and so
// are not matched by the address.
func (t *ReachabilityTable) ConntrackFlushTargets() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var ips []string
	if t.applied != nil {
		ips = lostAccess(t.applied, t.built)
	}
	for _, a := range t.builtDedicated {
		if !slices.Contains(t.appliedDedicated, a) {
			ips = append(ips, a)
		}
	}
	t.applied, t.appliedDedicated = t.built, t.builtDedicated
	return ips
}

// dedicatedAddrs is every extra internet address any network or device names, enforced or not,
// once each and sorted: the dedicated_addrs set.
func dedicatedAddrs(pol map[int64]netPolicy) []string {
	var out []string
	for _, p := range pol {
		for _, a := range p.Dedicated {
			if ip := dedicatedIP(a); ip != "" && !slices.Contains(out, ip) {
				out = append(out, ip)
			}
		}
	}
	sort.Strings(out)
	return out
}

// traefikOrigin resolves Traefik's origin when a domain route needs it. The rules trust Traefik's
// source address on its network, so they are only written while no other container there could
// forge it (helper.ContainersAbleToForge); when that or the origin can't be established, every
// route to a LAN device stays shut and the reason is logged.
func traefikOrigin(pol map[int64]netPolicy) routeOrigin {
	for _, p := range pol {
		for _, d := range p.Devices {
			if len(d.Routes) == 0 {
				continue
			}
			iface, ip, err := helper.TraefikOrigin()
			if err != nil {
				log.Printf("dhcp: domain routes to LAN devices stay shut: %v", err)
				return routeOrigin{}
			}
			forgers, err := helper.ContainersAbleToForge(ip)
			if err != nil {
				log.Printf("dhcp: domain routes to LAN devices stay shut: can't check the containers on %s: %v", helper.DockerNetwork, err)
				return routeOrigin{}
			}
			if len(forgers) > 0 {
				log.Printf("dhcp: domain routes to LAN devices stay shut: %s on %s could forge Traefik's address (drop NET_RAW, no NET_ADMIN or privileged)", strings.Join(forgers, ", "), helper.DockerNetwork)
				return routeOrigin{}
			}
			return routeOrigin{Iface: iface, IP: ip.String()}
		}
	}
	return routeOrigin{}
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
	acl, err := s.networkGrants(n.ID)
	if err != nil {
		return p, err
	}
	space, err := s.loadVPNSpace()
	if err != nil {
		return p, err
	}
	routes, err := s.networkRoutePorts(n.ID)
	if err != nil {
		return p, err
	}
	if ip := dedicatedIP(n.Egress); ip != "" {
		p.Dedicated = append(p.Dedicated, ip)
	}
	for _, c := range clients {
		if ip := dedicatedIP(c.Egress); ip != "" {
			p.Dedicated = append(p.Dedicated, ip)
		}
	}
	_, cnet, err := net.ParseCIDR(n.CIDR)
	if err != nil {
		return p, nil // an invalid network renders nothing (renderReachability skips it too)
	}
	var egress egressResolver
	for i := range clients {
		c := &clients[i]
		if c.Blocked {
			p.Blocked = append(p.Blocked, strings.ToLower(c.MAC))
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(c.IP))
		mac := strings.ToLower(c.MAC)
		if !c.Approved || ip == nil || ip.To4() == nil || !cnet.Contains(ip) || !validMAC(mac) {
			continue
		}
		d := devicePolicy{IP: ip.String(), MAC: mac, Allowed: acl[c.ID], Internet: c.Internet}
		if d.Internet {
			d.Egress, d.Internet = egress.resolve(n, c)
			d.Out = portsOf(effectiveServices(n, c))
		}
		if space.usable(c.VPNIP) {
			d.VPNIP, d.Routes = c.VPNIP, routes[c.ID]
		} else if c.VPNIP != "" {
			log.Printf("dhcp: LAN device %s: VPN address %s is not usable (outside the WireGuard range or also held by a VPN client); not reachable through it", mac, c.VPNIP)
		}
		p.Devices = append(p.Devices, d)
	}
	return p, nil
}

// enforced reports whether a network's rules are rendered: enabled, with a valid interface and
// subnet (defensive: never emit an unvalidated name or CIDR).
func (n *Network) enforced() bool {
	_, _, err := net.ParseCIDR(n.CIDR)
	return n.Enabled && validIface(n.Iface) && err == nil
}

// HeadscaleGrant is a LAN device's access for one Headscale node, for the Headscale policy: the node
// may reach VPNIP and, Both, VPNIP the node. The nft rules stay the gate; without this entry
// Headscale itself drops the traffic before it ever reaches the box.
type HeadscaleGrant struct {
	ClientID int64
	VPNIP    string
	Both     bool
}

// HeadscaleGrants lists them for every device the firewall currently lets through by its VPN
// address, so the policy never grants more than the rules do.
func HeadscaleGrants(db *database.DB) ([]HeadscaleGrant, error) {
	s := &Service{db: db}
	nets, err := s.listNetworks()
	if err != nil {
		return nil, err
	}
	var out []HeadscaleGrant
	for i := range nets {
		if !nets[i].enforced() {
			continue
		}
		p, err := s.networkPolicy(&nets[i])
		if err != nil {
			return nil, err
		}
		for _, d := range p.Devices {
			if d.VPNIP == "" {
				continue
			}
			for _, g := range d.Allowed {
				if g.Headscale && net.ParseIP(g.IP) != nil {
					out = append(out, HeadscaleGrant{ClientID: g.ClientID, VPNIP: d.VPNIP, Both: g.Both})
				}
			}
		}
	}
	return out, nil
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
func renderReachability(nets []Network, pol map[int64]netPolicy, wan string, privateRanges []string, traefik routeOrigin) string {
	var blk, fwd, in, dnat, nat strings.Builder
	for i := range nets {
		n := &nets[i]
		if !n.enforced() {
			continue
		}
		p := pol[n.ID]
		fmt.Fprintf(&fwd, "        # network %s (%s, %s)\n", n.Iface, n.CIDR, n.Mode)

		// IPv4 only: every rule below matches IPv4 addresses, so routed IPv6 to or from the segment
		// would pass them all (grants, the internet switch, the services). It is dropped outright,
		// above the established/related accept so an open IPv6 connection is cut as well.
		fmt.Fprintf(&blk, "        iifname %q meta nfproto ipv6 drop\n", n.Iface)
		fmt.Fprintf(&blk, "        oifname %q meta nfproto ipv6 drop\n", n.Iface)

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

		// Approved devices are matched by IP + MAC on everything they send, so a device that sets an
		// approved one's IP by hand gets none of its access. (A MAC can be cloned too, but only by
		// someone who has seen the real device on this LAN.)
		var devices []devicePolicy
		for _, d := range p.Devices {
			if net.ParseIP(d.IP) != nil && validMAC(d.MAC) {
				devices = append(devices, d)
			}
		}
		from := func(d devicePolicy) string {
			return fmt.Sprintf("iifname %q ether saddr %s ip saddr %s", n.Iface, d.MAC, d.IP)
		}

		// Per-device access: each granted VPN client reaches that one device; a two-way grant lets
		// the device reach the client too, like the VPN ACL. Emitted ABOVE the private-range drop
		// below so a granted client inside a VPN range stays reachable.
		for _, d := range devices {
			granted, both := false, false
			for _, g := range d.Allowed {
				if net.ParseIP(g.IP) == nil {
					continue
				}
				granted = true
				fmt.Fprintf(&fwd, "        ip saddr %s ip daddr %s accept\n", g.IP, d.IP)
				if g.Both {
					both = true
					fmt.Fprintf(&fwd, "        %s ip daddr %s accept\n", from(d), g.IP)
				}
			}
			// Domain routes: Traefik, and only Traefik (its address on its own Docker bridge), reaches
			// the device on the routes' ports through its VPN address. The forward rule only takes
			// traffic that came through that swap, so Traefik still can't reach the device directly.
			if ports := portSet(d.Routes); ports != "" && net.ParseIP(d.VPNIP).To4() != nil &&
				validIface(traefik.Iface) && net.ParseIP(traefik.IP).To4() != nil {
				fmt.Fprintf(&dnat, "        iifname %q ip saddr %s ip daddr %s tcp dport %s dnat ip to %s\n", traefik.Iface, traefik.IP, d.VPNIP, ports, d.IP)
				fmt.Fprintf(&fwd, "        iifname %q ip saddr %s ip daddr %s tcp dport %s ct status dnat accept\n", traefik.Iface, traefik.IP, d.IP, ports)
			}
			// The VPN address swap. In: what reaches the VPN address over a VPN interface goes to the
			// device (never from the WAN or a LAN); the forward rules above still decide who gets
			// through, as they see the device's real address. Out: only for a two-way grant, the
			// device's own connections into the VPN leave from its VPN address so replies find it.
			if !granted || net.ParseIP(d.VPNIP).To4() == nil {
				continue
			}
			fmt.Fprintf(&dnat, "        iifname %s ip daddr %s dnat ip to %s\n", nftables.VPNIfaces, d.VPNIP, d.IP)
			if both {
				fmt.Fprintf(&nat, "        iifname %q ip saddr %s oifname %s snat ip to %s\n", n.Iface, d.IP, nftables.VPNIfaces, d.VPNIP)
			}
		}

		// The box itself: every device may get an address (DHCP) and resolve names (DNS); only
		// approved ones reach anything else on it (SSH, the panel API, ...). Without this a device
		// still waiting for approval could reach every service open on non-WAN interfaces.
		fmt.Fprintf(&in, "        iifname %q udp dport 67 accept\n", n.Iface)
		fmt.Fprintf(&in, "        iifname %q meta l4proto { tcp, udp } th dport 53 accept\n", n.Iface)
		for _, d := range devices {
			fmt.Fprintf(&in, "        %s accept\n", from(d))
		}
		fmt.Fprintf(&in, "        iifname %q drop\n", n.Iface)

		// Internet-out, per device: only devices with it on reach the PUBLIC internet, each leaving
		// from its internet address (masqueraded to the main one, or SNAT to an extra one).
		if p.hasInternet() && validIface(wan) {
			// Leak guard: refuse the segment → private/VPN ranges BEFORE the WAN accept, so a
			// destination that merely routes via the WAN NIC (e.g. a datacenter 10.0.0.0/8) is
			// dropped instead of silently masqueraded out. Its own subnet is excluded (local, and
			// never forwarded anyway); the access pairs above already cleared any granted VPN client.
			if len(privateRanges) > 0 {
				fmt.Fprintf(&fwd, "        ip saddr %s ip daddr @private_ranges ip daddr != %s drop\n", n.CIDR, n.CIDR)
			}
			for _, d := range devices {
				via, ok := d.internetVia()
				if !ok || !d.Out.any() {
					continue // no way out at all: no NAT either
				}
				writeInternetOut(&fwd, from(d), wan, d.Out)
				if via == "" {
					fmt.Fprintf(&nat, "        ip saddr %s oifname %q masquerade\n", d.IP, wan)
				} else {
					fmt.Fprintf(&nat, "        ip saddr %s oifname %q snat ip to %s\n", d.IP, wan, via)
				}
			}
		}

		// Default-deny: nothing else reaches the segment, and the segment initiates nothing
		// else (replies ride ct established,related at the top). True sandbox when NAT is off.
		fmt.Fprintf(&fwd, "        ip daddr %s drop\n", n.CIDR)
		fmt.Fprintf(&fwd, "        ip saddr %s drop\n\n", n.CIDR)
	}

	dedicated := dedicatedAddrs(pol)

	var sb strings.Builder
	sb.WriteString("table inet motte_dhcp_net {\n")
	// private_ranges: destinations a segment must never reach via internet-out (every non-public
	// block + the live VPN/overlay ranges). Interval+auto-merge so overlapping CIDRs collapse cleanly.
	sb.WriteString(nftables.BuildSet("private_ranges", "ipv4_addr", []string{"interval", "auto-merge"}, privateRanges))
	// dedicated_addrs: the extra internet addresses. Nothing may open a connection to them — no
	// service on the box, no Docker-published port, not even ping; only the devices' own
	// connections and their replies (and related ICMP errors) pass. Priority -150 runs after
	// conntrack (-200) has classified the packet and before Docker's port forwarding (dstnat,
	// -100), so a published container port can't answer on them either. A service opened on one
	// later goes above the drop, as an accept for exactly that port and those sources.
	sb.WriteString(nftables.BuildSet("dedicated_addrs", "ipv4_addr", nil, dedicated))
	sb.WriteString("    chain dedicated_in {\n")
	sb.WriteString("        type filter hook prerouting priority -150; policy accept;\n")
	sb.WriteString("        ip daddr @dedicated_addrs ct state != { established, related } drop\n")
	sb.WriteString("    }\n")
	sb.WriteString("    chain forward {\n")
	sb.WriteString("        type filter hook forward priority 10; policy accept;\n")
	sb.WriteString(blk.String())
	sb.WriteString("        ct state established,related accept\n")
	sb.WriteString(fwd.String())
	sb.WriteString("    }\n")
	// The box itself: blocked devices dropped, then per network only DHCP, DNS and approved devices.
	// A drop is final across base chains, so this holds whatever the host firewall's input accepts.
	sb.WriteString("    chain input {\n")
	sb.WriteString("        type filter hook input priority 10; policy accept;\n")
	sb.WriteString(in.String())
	sb.WriteString("    }\n")
	sb.WriteString("    chain prerouting {\n")
	sb.WriteString("        type nat hook prerouting priority dstnat; policy accept;\n")
	sb.WriteString(dnat.String())
	sb.WriteString("    }\n")
	sb.WriteString("    chain postrouting {\n")
	sb.WriteString("        type nat hook postrouting priority 100; policy accept;\n")
	sb.WriteString(nat.String())
	sb.WriteString("    }\n")
	sb.WriteString("}\n")
	return sb.String()
}

// writeInternetOut emits a device's way out to the internet: only its listed ports, or every
// port except those of the services it wasn't given (dropped first). Anything else falls to the
// network's closing drop.
func writeInternetOut(b *strings.Builder, from, wan string, o outPorts) {
	out := fmt.Sprintf("%s oifname %q", from, wan)
	if o.All {
		if ports := portSet(o.BlockTCP); ports != "" {
			fmt.Fprintf(b, "        %s tcp dport %s drop\n", out, ports)
		}
		if ports := portSet(o.BlockUDP); ports != "" {
			fmt.Fprintf(b, "        %s udp dport %s drop\n", out, ports)
		}
		fmt.Fprintf(b, "        %s accept\n", out)
		return
	}
	if ports := portSet(o.TCP); ports != "" {
		fmt.Fprintf(b, "        %s tcp dport %s accept\n", out, ports)
	}
	if ports := portSet(o.UDP); ports != "" {
		fmt.Fprintf(b, "        %s udp dport %s accept\n", out, ports)
	}
}

// portSet renders ports as an nft port or anonymous set, keeping only valid ports; "" when
// none is.
func portSet(ports []int) string {
	var ok []string
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			ok = append(ok, strconv.Itoa(p))
		}
	}
	switch len(ok) {
	case 0:
		return ""
	case 1:
		return ok[0]
	}
	return "{ " + strings.Join(ok, ", ") + " }"
}

// ensureIPForward enables IPv4 forwarding (needed to route between wg0 and the segment). Writes
// the shared-netns proc file directly — no extra binary, and it's the host's netns since the api
// is host-networked. Best-effort: forwarding may already be on from the WireGuard setup.
func ensureIPForward() {
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
}
