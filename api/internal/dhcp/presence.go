package dhcp

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"api/internal/helper"
	"api/internal/routines"
)

// Presence: whether a LAN device is really there, not just holding a lease. A lease lasts hours,
// so a machine that is switched off or deleted would otherwise show online until it runs out (and
// could not be forgotten meanwhile). Once a minute (a routine, so it never overlaps itself, stops
// with the api and shows on the Routines page) the kernel's neighbour table is read for each
// enabled network: a device whose IP answers with its own MAC is seen. One the kernel hasn't
// confirmed lately gets a single empty UDP datagram (to the discard port, nothing listens), which
// makes the kernel ask for it on the LAN; every IPv4 device answers that (ARP), firewall or not.
// After a short wait the table is read again. Nothing is kept in memory between rounds but the
// time of the last good one: last_seen lives in the database.

const (
	presenceInterval = time.Minute
	// presenceWindow: a device not seen for this long is offline, whatever its lease says.
	presenceWindow = 3 * time.Minute
	// presenceWrite: last_seen is rewritten at most this often for a device that stays seen.
	presenceWrite = 50 * time.Second
	// presenceDiscardPort is where the nudge goes: the discard service, which takes nothing back.
	presenceDiscardPort = "9"
)

// Stand-ins for tests: reading the neighbour table, nudging an address and the settle wait.
var (
	readNeighbors = func(iface string) (string, error) {
		out, err := helper.Command("ip", "-4", "neigh", "show", "dev", iface).Output()
		return string(out), err
	}
	nudgeAddress = func(ip string) {
		if c, err := net.Dial("udp4", net.JoinHostPort(ip, presenceDiscardPort)); err == nil {
			_, _ = c.Write([]byte{0})
			_ = c.Close()
		}
	}
	presenceSettle = 10 * time.Second
)

// lastPresence is when the last round read every network's neighbours (unix seconds; 0 = never).
var lastPresence atomic.Int64

// neighbor is one row of the neighbour table.
type neighbor struct {
	MAC   string
	State string
}

// parseNeighbors reads `ip -4 neigh show dev X` output: "<ip> lladdr <mac> <STATE>" (an entry
// that never resolved has no lladdr).
func parseNeighbors(out string) map[string]neighbor {
	m := map[string]neighbor{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || net.ParseIP(f[0]).To4() == nil {
			continue
		}
		var n neighbor
		for i := 1; i < len(f)-1; i++ {
			if f[i] == "lladdr" && validMAC(strings.ToLower(f[i+1])) {
				n.MAC = strings.ToLower(f[i+1])
			}
		}
		n.State = f[len(f)-1]
		m[f[0]] = n
	}
	return m
}

// confirmed reports whether the neighbour table shows mac answering for ip just now.
func confirmed(nb map[string]neighbor, ip, mac string) bool {
	n, ok := nb[ip]
	return ok && mac != "" && n.MAC == mac && n.State == "REACHABLE"
}

// presenceKnown reports whether presence has been checked recently enough to go by; when it
// hasn't (the routine is paused, or the table can't be read), a lease alone counts as online, as
// before presence existed.
func presenceKnown() bool {
	at := lastPresence.Load()
	return at > 0 && time.Since(time.Unix(at, 0)) < presenceWindow
}

// seenRecently reports whether a stored last_seen is within the presence window.
func seenRecently(lastSeen string) bool {
	t, err := time.Parse(time.RFC3339, lastSeen)
	return err == nil && time.Since(t) < presenceWindow
}

// presenceTarget is one network's leased devices for a round.
type presenceTarget struct {
	net    Network
	leases []lease
}

// RegisterPresence starts the presence routine.
func (s *Service) RegisterPresence() {
	routines.Register(routines.Spec{
		Name:        "lan-presence",
		Description: "Check which LAN devices are really online (neighbour table, ARP)",
		Interval:    presenceInterval,
		RunAtStart:  true,
		Run:         s.checkPresence,
	})
}

// checkPresence runs one round over every enabled network with leases.
func (s *Service) checkPresence(ctx context.Context) error {
	nets, err := s.listNetworks()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	var targets []presenceTarget
	for _, n := range nets {
		if !n.enforced() {
			continue
		}
		_, cnet, _ := net.ParseCIDR(n.CIDR)
		var leases []lease
		for _, l := range parseLeases(n.Iface) {
			// Only addresses inside the network: the lease file never steers a packet elsewhere.
			if ip := net.ParseIP(l.IP).To4(); ip != nil && cnet.Contains(ip) && (l.Expiry == 0 || l.Expiry > now) {
				leases = append(leases, l)
			}
		}
		if len(leases) > 0 {
			targets = append(targets, presenceTarget{net: n, leases: leases})
		}
	}
	if len(targets) == 0 {
		lastPresence.Store(time.Now().Unix())
		return nil
	}

	// Nudge every leased device the kernel hasn't confirmed, then give the answers time to come.
	failed := 0
	nudged := false
	for _, t := range targets {
		out, err := readNeighbors(t.net.Iface)
		if err != nil {
			failed++
			continue
		}
		nb := parseNeighbors(out)
		for _, l := range t.leases {
			if !confirmed(nb, l.IP, l.MAC) {
				nudgeAddress(l.IP)
				nudged = true
			}
		}
	}
	if nudged {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(presenceSettle):
		}
	}

	stamp := time.Now().UTC()
	for _, t := range targets {
		out, err := readNeighbors(t.net.Iface)
		if err != nil {
			failed++
			continue
		}
		nb := parseNeighbors(out)
		for _, l := range t.leases {
			if confirmed(nb, l.IP, l.MAC) {
				s.markSeen(t.net.ID, l.MAC, stamp)
			}
		}
	}
	if failed > 0 {
		return fmt.Errorf("could not read the neighbour table of %d network(s)", failed)
	}
	lastPresence.Store(stamp.Unix())
	return nil
}

// markSeen records a device as seen at t, rewriting last_seen at most every presenceWrite.
func (s *Service) markSeen(networkID int64, mac string, t time.Time) {
	if _, err := s.db.Exec(`UPDATE dhcp_clients SET last_seen = ? WHERE network_id = ? AND mac = ?
		AND (last_seen IS NULL OR last_seen < ?)`,
		t.Format(time.RFC3339), networkID, mac, t.Add(-presenceWrite).Format(time.RFC3339)); err != nil {
		log.Printf("dhcp: presence: %v", err)
	}
}

// rememberForgotten notes that a device was forgotten while dnsmasq still holds its lease, so the
// lease file doesn't bring it straight back. A renewed lease (the device really returned) or the
// lease running out ends the note (syncLeases).
func (s *Service) rememberForgotten(n *Network, mac string) {
	mac = strings.ToLower(mac)
	for _, l := range parseLeases(n.Iface) {
		if l.MAC == mac {
			if _, err := s.db.Exec(`INSERT INTO dhcp_forgotten (mac, lease_expiry) VALUES (?, ?)
				ON CONFLICT(mac) DO UPDATE SET lease_expiry = excluded.lease_expiry`, mac, l.Expiry); err != nil {
				log.Printf("dhcp: remember forgotten %s: %v", mac, err)
			}
			return
		}
	}
}

// forgottenLeases returns the forgotten devices' leases (MAC → lease end), dropping the notes
// whose lease has run out.
func (s *Service) forgottenLeases() map[string]int64 {
	_, _ = s.db.Exec(`DELETE FROM dhcp_forgotten WHERE lease_expiry > 0 AND lease_expiry < ?`, time.Now().Unix())
	out := map[string]int64{}
	rows, err := s.db.Query(`SELECT mac, lease_expiry FROM dhcp_forgotten`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var mac string
		var exp int64
		if rows.Scan(&mac, &exp) == nil {
			out[mac] = exp
		}
	}
	return out
}
