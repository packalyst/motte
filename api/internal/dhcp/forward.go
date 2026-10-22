package dhcp

import (
	"log"
	"os/exec"
)

// Docker sets the host's FORWARD chain to policy DROP (priority 0) and only accepts its own bridge
// traffic. A packet routed between a managed segment NIC and the WAN is not Docker's, matches
// nothing, and hits that drop BEFORE it reaches our reachability chain (inet wgadmin_dhcp_net,
// priority +10) — an accept there can't rescue a packet an earlier base chain already dropped.
// WireGuard faces the same wall and gets past it with `FORWARD -i/-o wg0 accept` (see
// wireguard.setupNAT), which is also why VPN↔segment forwarding already works: it rides those wg0
// rules. The ONLY gap is segment↔WAN, so that is the only path we punch, and only when the network
// has internet-out (NAT) enabled.
//
// Scope is deliberately tight (defense-in-depth):
//   - segment → WAN: `-i <seg> -o <wan> accept`
//   - WAN → segment: `-i <wan> -o <seg> -m conntrack --ctstate ESTABLISHED,RELATED accept` (replies only)
// Docker's isolation therefore stays intact for every other destination (other segments, container
// bridges), and unsolicited WAN→segment is refused at Docker as well as at the nft gate. The real
// approve/pending/sandbox filtering still lives in the nft reachability chain; this only lifts
// Docker's blanket drop on the one path that needs it.
//
// iptables mutates the same nft ruleset here (iptables-nft) but is the only safe way to add to the
// "managed by iptables-nft, do not touch" ip filter table; the api image ships iptables and already
// uses it for WG NAT and virtual IPs. All calls are idempotent (-C before -A) and best-effort.

// iptablesForward runs `iptables <op> FORWARD <args...> -j ACCEPT` (op is -C/-A/-D).
func iptablesForward(op string, args ...string) error {
	full := append([]string{op, "FORWARD"}, args...)
	full = append(full, "-j", "ACCEPT")
	return exec.Command("iptables", full...).Run()
}

// ensureForward adds a FORWARD accept if it isn't already present (idempotent via -C).
func ensureForward(args ...string) {
	if iptablesForward("-C", args...) != nil {
		if err := iptablesForward("-A", args...); err != nil {
			log.Printf("dhcp: add FORWARD accept %v failed: %v", args, err)
		}
	}
}

// delForward removes a FORWARD accept; best-effort, a "rule not present" error is ignored.
func delForward(args ...string) { _ = iptablesForward("-D", args...) }

// segmentWANRules returns the two FORWARD accept rule-arg sets (out, back) for a segment↔WAN path.
func segmentWANRules(seg, wan string) (out, back []string) {
	out = []string{"-i", seg, "-o", wan}
	back = []string{"-i", wan, "-o", seg, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"}
	return
}

// syncSegmentForward brings the Docker FORWARD punch-through in line with a network's current
// state: open the scoped segment↔WAN path only when the network is enabled AND at least one of its
// devices has internet access (which device may actually use it is decided in the nft
// reachability chain), close it otherwise. It also clears the broad `-i/-o <iface>` rules an
// earlier version added, so an upgrade tightens an already-running network without a manual cleanup.
func syncSegmentForward(n *Network, internet bool) {
	// Migration: drop the first implementation's broad rules if present.
	delForward("-i", n.Iface)
	delForward("-o", n.Iface)

	wan, _ := defaultRouteInterface()
	out, back := segmentWANRules(n.Iface, wan)

	if n.Enabled && internet && validIface(n.Iface) && validIface(wan) {
		ensureForward(out...)  // segment → WAN
		ensureForward(back...) // WAN → segment (replies only)
		return
	}
	// No device with internet, or disabled: ensure the WAN path is closed.
	delForward(out...)
	delForward(back...)
}

// removeSegmentForward tears down every FORWARD accept we might have added for a segment NIC — the
// broad legacy rules and the scoped WAN-path rules — used when a network is disabled or deleted.
func removeSegmentForward(iface string) {
	if !validIface(iface) {
		return
	}
	delForward("-i", iface)
	delForward("-o", iface)
	if wan, _ := defaultRouteInterface(); validIface(wan) {
		out, back := segmentWANRules(iface, wan)
		delForward(out...)
		delForward(back...)
	}
}
