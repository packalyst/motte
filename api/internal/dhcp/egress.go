package dhcp

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"

	"api/internal/helper"
)

// The internet address: which of the server's public IPv4 addresses a LAN device's internet
// traffic leaves from. A network sets the default for its devices ("" = the server's main
// address); a device may pick its own ("" = its network's default, egressMain = the main address
// whatever the network says). Every extra address takes nothing in (renderReachability's
// dedicated_in chain) and has one of two roles, set by who picks it:
//   - shared: networks' default, used by all their devices (several networks may share one);
//   - dedicated: picked on one device, which then owns it alone.
// No address is both, and no two devices own the same one: a save that would do so is refused,
// and stored data that does anyway (egressClaims.conflict) leaves everyone on that address without
// internet rather than guessing who it belongs to. An address that is no longer on the server
// leaves the devices using it with no internet: they never fall back to another address.

// egressMain is a device's explicit choice of the server's main address.
const egressMain = "main"

// egressAddrs is what the server offers: Main, the address it sends its own traffic from, and
// Extras, the other public IPv4 addresses on its internet interface.
type egressAddrs struct {
	Main   string   `json:"main"`
	Extras []string `json:"extras"`
	// Use is who holds each extra address now (filled for the UI by egressOffer).
	Use map[string]egressUse `json:"use,omitempty"`
}

// egressUse is who holds one extra address: the networks sharing it and the devices it is
// dedicated to (more than one of either kind, or both kinds, is a conflict).
type egressUse struct {
	Networks []string      `json:"networks,omitempty"` // their interfaces
	Devices  []egressOwner `json:"devices,omitempty"`
}

type egressOwner struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// egressClaims is who holds each extra address, keyed by the address.
type egressClaims map[string]egressUse

// conflict reports whether ip is held in a way that can't be honoured: shared and dedicated at
// once, or dedicated to more than one device.
func (e egressClaims) conflict(ip string) bool {
	u := e[ip]
	return len(u.Devices) > 1 || (len(u.Devices) > 0 && len(u.Networks) > 0)
}

// loadEgressClaims reads who holds each extra address from the stored choices.
func (s *Service) loadEgressClaims() (egressClaims, error) {
	claims := egressClaims{}
	rows, err := s.db.Query(`SELECT iface, egress_ip FROM dhcp_networks`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var iface, v string
		if err := rows.Scan(&iface, &v); err != nil {
			rows.Close()
			return nil, err
		}
		if ip := dedicatedIP(v); ip != "" {
			u := claims[ip]
			u.Networks = append(u.Networks, iface)
			claims[ip] = u
		}
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT id, name, mac, egress_ip FROM dhcp_clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ID, &c.Name, &c.MAC, &c.Egress); err != nil {
			return nil, err
		}
		if ip := dedicatedIP(c.Egress); ip != "" {
			u := claims[ip]
			u.Devices = append(u.Devices, egressOwner{ID: c.ID, Name: c.label()})
			claims[ip] = u
		}
	}
	return claims, rows.Err()
}

// egressOffer is what the UI offers: the server's addresses and who holds each extra one.
func (s *Service) egressOffer() egressAddrs {
	e, _ := loadEgressAddrs() // none offered when the host can't be read
	if claims, err := s.loadEgressClaims(); err == nil {
		e.Use = claims
	}
	return e
}

// egressMu serializes the saves that pick an address, so two at once can't both take one.
var egressMu sync.Mutex

// wanAddresses reads the host (a variable so tests can stand in for it).
var wanAddresses = helper.WANAddresses

// loadEgressAddrs reads the server's internet addresses. An extra is public IPv4, never the
// address the server sends from, and never SERVER_IP (the panel's own public address).
func loadEgressAddrs() (egressAddrs, error) {
	_, src, addrs, err := wanAddresses()
	if err != nil {
		return egressAddrs{Extras: []string{}}, err
	}
	panel := helper.GetEnvOptional("SERVER_IP", "")
	out := egressAddrs{Main: src, Extras: []string{}}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip.To4() == nil || helper.IsNonPublicIP(ip) || a == src || a == panel {
			continue
		}
		out.Extras = append(out.Extras, a)
	}
	sort.Strings(out.Extras)
	return out, nil
}

func (e egressAddrs) has(ip string) bool {
	for _, x := range e.Extras {
		if x == ip {
			return true
		}
	}
	return false
}

// dedicatedIP returns v as an extra address when it names one ("" for the main address, the
// network default, or anything that isn't an IPv4 address).
func dedicatedIP(v string) string {
	if ip := net.ParseIP(v); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	return ""
}

// checkEgress validates a chosen internet address and returns it normalized: "" always passes,
// egressMain only for a device (devID set; 0 is a network choosing), anything else must be an
// extra address on the server right now that the chooser may hold: a network may share an address
// no device owns; a device may own one no network shares and no other device owns. Callers hold
// egressMu from this check until the choice is saved.
func (s *Service) checkEgress(v string, devID int64) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || (devID != 0 && v == egressMain) {
		return v, nil
	}
	ip := dedicatedIP(v)
	if ip == "" {
		return "", fmt.Errorf("internet address must be an IPv4 address")
	}
	e, err := loadEgressAddrs()
	if err != nil {
		return "", fmt.Errorf("could not read the server's addresses: %v", err)
	}
	if !e.has(ip) {
		return "", fmt.Errorf("%s is not an extra public address on the server's internet interface", ip)
	}
	claims, err := s.loadEgressClaims()
	if err != nil {
		return "", fmt.Errorf("could not read which addresses are in use")
	}
	u := claims[ip]
	for _, d := range u.Devices {
		if d.ID != devID {
			return "", fmt.Errorf("%s is dedicated to %s", ip, d.Name)
		}
	}
	if devID != 0 && len(u.Networks) > 0 {
		return "", fmt.Errorf("%s is shared by network %s; a device can only own an address no network uses", ip, strings.Join(u.Networks, ", "))
	}
	return ip, nil
}

// checkOwnEgress re-checks the address a device already has stored before its internet is turned
// back on: it must still be one the device may hold.
func (s *Service) checkOwnEgress(c *Client) error {
	if dedicatedIP(c.Egress) == "" {
		return nil
	}
	_, err := s.checkEgress(c.Egress, c.ID)
	return err
}

// egressResolver resolves devices' internet addresses for one policy build, reading the host at
// most once and only when an extra address is actually in use. claims is who holds each address.
type egressResolver struct {
	claims egressClaims
	addrs  *egressAddrs
	loaded bool
}

// resolve returns the address a device leaves from ("" = the main address) and whether it may
// go out at all: false when its address is gone from the server (fail closed).
func (r *egressResolver) resolve(n *Network, c *Client) (string, bool) {
	v := c.Egress
	if v == "" {
		v = n.Egress
	}
	if v == "" || v == egressMain {
		return "", true
	}
	ip := dedicatedIP(v)
	if !r.loaded {
		r.loaded = true
		if e, err := loadEgressAddrs(); err == nil {
			r.addrs = &e
		} else {
			log.Printf("dhcp: could not read the server's internet addresses: %v", err)
		}
	}
	if ip == "" || r.addrs == nil || !r.addrs.has(ip) {
		log.Printf("dhcp: LAN device %s: internet address %s is not on the server; it has no internet until it is", c.MAC, v)
		return "", false
	}
	if r.claims.conflict(ip) {
		log.Printf("dhcp: LAN device %s: internet address %s is held by more than one network or device; it has no internet until one is moved", c.MAC, ip)
		return "", false
	}
	return ip, true
}
