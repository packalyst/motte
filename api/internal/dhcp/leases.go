package dhcp

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// apiLeaseDir is the api's mount of the shared lease volume (dnsmasq writes leases there at
// /var/lib/misc). One file per network keeps parsing simple and per-network.
const apiLeaseDir = "/dhcp-leases"

func apiLeasePath(iface string) string { return apiLeaseDir + "/wgpanel-" + iface + ".leases" }

// removeLeaseFile deletes a network's dnsmasq lease file from the shared volume when the network is
// deleted, so a network later created on the same NIC doesn't inherit stale leases (old devices
// re-appearing, recycled IPs). Best-effort; guarded by validIface since the path is built from the
// interface name.
func removeLeaseFile(iface string) {
	if !validIface(iface) {
		return
	}
	_ = os.Remove(apiLeasePath(iface))
}

type lease struct {
	MAC    string
	IP     string
	Name   string
	Expiry int64 // unix seconds; 0 = never expires
}

// parseLeases reads dnsmasq's lease file for a network. Format per line:
//
//	<expiry-epoch> <mac> <ip> <hostname> <client-id>
//
// Unreadable/missing file → no leases (the network may just have none yet).
func parseLeases(iface string) []lease {
	f, err := os.Open(apiLeasePath(iface))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []lease
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		exp, _ := strconv.ParseInt(fields[0], 10, 64)
		l := lease{Expiry: exp, MAC: strings.ToLower(fields[1]), IP: fields[2]}
		if len(fields) >= 4 && fields[3] != "*" {
			l.Name = fields[3]
		}
		if validMAC(l.MAC) {
			out = append(out, l)
		}
	}
	return out
}

// syncLeases records every MAC currently seen on a network into dhcp_clients (auto-approved when
// the network is in "auto" mode), so devices appear in the UI. Called before listing.
func (s *Service) syncLeases(n *Network) {
	auto := n.Mode == "auto"
	for _, l := range parseLeases(n.Iface) {
		_ = s.upsertClient(n.ID, l.MAC, l.IP, l.Name, auto)
	}
}

// sanitizeLeaseName keeps a DHCP-advertised hostname safe/sane for display: trims it, drops the
// "*" placeholder and control characters, and caps the length. Empty if nothing usable is left.
func sanitizeLeaseName(s string) string {
	s = strings.TrimSpace(s)
	if s == "*" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f { // strip control chars
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 63 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// clientsWithLive returns the network's known clients (from the DB) with Online set from the live
// lease file (present and unexpired).
func (s *Service) clientsWithLive(n *Network) ([]Client, error) {
	s.syncLeases(n)
	clients, err := s.listClients(n.ID)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	online := map[string]bool{}
	for _, l := range parseLeases(n.Iface) {
		if l.Expiry == 0 || l.Expiry > now {
			online[l.MAC] = true
		}
	}
	for i := range clients {
		clients[i].Online = online[strings.ToLower(clients[i].MAC)]
	}
	return clients, nil
}
