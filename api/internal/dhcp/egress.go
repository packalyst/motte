package dhcp

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

	"api/internal/helper"
)

// The internet address: which of the server's public IPv4 addresses a LAN device's internet
// traffic leaves from. A network sets the default for its devices ("" = the server's main
// address); a device may pick its own ("" = its network's default, egressMain = the main address
// whatever the network says). An extra address picked here is dedicated: nothing may connect in
// to it (renderReachability's dedicated_in chain), it only carries the devices' own connections
// and their replies. An address that is no longer on the server leaves the devices using it with
// no internet: they never fall back to another address.

// egressMain is a device's explicit choice of the server's main address.
const egressMain = "main"

// egressAddrs is what the server offers: Main, the address it sends its own traffic from, and
// Extras, the other public IPv4 addresses on its internet interface.
type egressAddrs struct {
	Main   string   `json:"main"`
	Extras []string `json:"extras"`
}

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
// egressMain only for a device (allowMain), anything else must be an extra address on the server
// right now.
func checkEgress(v string, allowMain bool) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || (allowMain && v == egressMain) {
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
	return ip, nil
}

// egressResolver resolves devices' internet addresses for one policy build, reading the host at
// most once and only when an extra address is actually in use.
type egressResolver struct {
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
	return ip, true
}
