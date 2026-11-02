package helper

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Route targets: where a domain route may send traffic. Traefik reaches whatever address a route
// names, so a route must never point at what only this server itself may reach: loopback, the
// panel's own Docker network (the containers behind Traefik), link-local (cloud metadata),
// unspecified or multicast addresses, or the panel's own services on any address of this server
// (its API, AdGuard's and Traefik's admin pages). An app on this server under another port stays
// routable.

var errInternalTarget = errors.New("that address is internal to this server; a route can't point at it")

// panelServicePorts are the ports of the panel's own admin services, from the environment.
func panelServicePorts() []int {
	var out []int
	for _, env := range []string{"API_PORT", "ADGUARD_PORT", "TRAEFIK_PORT"} {
		if p, err := strconv.Atoi(strings.TrimSpace(GetEnvOptional(env, ""))); err == nil && p > 0 && p <= 65535 {
			out = append(out, p)
		}
	}
	return out
}

// hostAddrs lists this server's own IPv4 addresses (the API shares the host's network).
var hostAddrs = func() []netip.Addr {
	var out []netip.Addr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok {
				out = append(out, ip)
			}
		}
	}
	return out
}

// CheckRouteTarget refuses a route target internal to this server (see above).
func CheckRouteTarget(ip string, port int) error {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !a.Is4() {
		return errors.New("the target must be an IPv4 address")
	}
	if a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return errInternalTarget
	}
	if p, isRange, err := ParseIPv4(DockerSubnet()); err == nil && isRange && p.Contains(a) {
		return errInternalTarget
	}
	if slices.Contains(hostAddrs(), a) && slices.Contains(panelServicePorts(), port) {
		return errors.New("that is one of the panel's own services; a route can't point at it")
	}
	return nil
}

// SystemDomains are the panel's own host names (its domain, the admin domain, the tunnel proxy):
// no route may take one over.
func SystemDomains() []string {
	var out []string
	for _, env := range []string{"SSL_DOMAIN", "ADMIN_DOMAIN", "PROXY_DOMAIN"} {
		if d := strings.ToLower(strings.TrimSpace(GetEnvOptional(env, ""))); d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}
