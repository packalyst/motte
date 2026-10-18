package dhcp

import (
	"log"
	"os/exec"
)

// Docker sets the host's `ip filter` FORWARD chain to policy DROP (priority 0) and only accepts
// its own bridge traffic. A packet routed between a managed segment NIC and the WAN is not
// Docker's, matches nothing, and hits that drop BEFORE it reaches our reachability chain
// (inet wgadmin_dhcp_net, priority +10) — an accept there can't rescue a packet an earlier base
// chain already dropped. WireGuard faces the same wall and gets past it with a blanket
// `FORWARD -i/-o wg0 accept` (see wireguard.setupNAT); we do the identical thing for each managed
// segment NIC. This only lifts Docker's blanket drop — the real approve/pending/sandbox filtering
// still lives in the nft reachability chain, and the firewall's source/geo drops still run first.
//
// iptables mutates the SAME nft ruleset here (iptables-nft), but it is the only safe way to add to
// the "managed by iptables-nft, do not touch" ip filter table. The api image ships iptables and
// already uses it for WG NAT and virtual IPs. All calls are idempotent (-C before -A) and
// best-effort: a failure is logged, not fatal — forwarding simply stays blocked until the next
// reconcile, exactly as the WG path behaves.

// ensureSegmentForward lets Docker's FORWARD chain pass traffic on a managed segment NIC, so
// segment→WAN (and segment↔VPN) routing survives Docker's policy-drop.
func ensureSegmentForward(iface string) {
	if !validIface(iface) {
		return
	}
	for _, dir := range []string{"-i", "-o"} {
		if exec.Command("iptables", "-C", "FORWARD", dir, iface, "-j", "ACCEPT").Run() != nil {
			if err := exec.Command("iptables", "-A", "FORWARD", dir, iface, "-j", "ACCEPT").Run(); err != nil {
				log.Printf("dhcp: add FORWARD accept (%s %s) failed: %v", dir, iface, err)
			}
		}
	}
}

// removeSegmentForward drops the FORWARD accepts for a segment NIC when it is disabled or deleted.
func removeSegmentForward(iface string) {
	if !validIface(iface) {
		return
	}
	for _, dir := range []string{"-i", "-o"} {
		// -D only what we added; ignore "rule not present" errors (best-effort cleanup).
		_ = exec.Command("iptables", "-D", "FORWARD", dir, iface, "-j", "ACCEPT").Run()
	}
}
