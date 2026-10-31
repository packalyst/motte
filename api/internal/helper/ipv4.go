package helper

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// The one place this codebase decides what an IPv4 value is and which addresses are not on
// the public internet. Firewall entries, nftables rule builders, the SSRF guard, the traffic
// logs, the phone-home watch, the fleet's public-IP pick and DHCP networks all read these.

var rfc1918 = mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

// nonPublicV4 is every IPv4 block that is not a public unicast address: RFC1918, loopback,
// link-local, multicast, CGNAT (100.64.0.0/10 — the Tailscale/Headscale overlay) and 0.0.0.0/8.
var nonPublicV4 = append(mustPrefixes(
	"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
), rfc1918...)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

var errIPv6 = errors.New("IPv6 is not supported (this panel is IPv4-only; external IPv6 is dropped at the firewall)")

// ParseIPv4 parses an IPv4 address or CIDR. A bare address comes back as a /32 with
// isRange false; a CIDR comes back masked to its network (1.2.3.4/24 → 1.2.3.0/24). Every
// IPv6 form is refused, including IPv4-mapped (::ffff:1.2.3.4): nftables' ipv4_addr sets
// reject it, and one bad element wedges the whole atomic ruleset reload.
func ParseIPv4(s string) (p netip.Prefix, isRange bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false, errors.New("empty input")
	}
	if strings.Contains(s, "/") {
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false, fmt.Errorf("invalid CIDR %q", s)
		}
		if !p.Addr().Is4() {
			return netip.Prefix{}, false, errIPv6
		}
		return p.Masked(), true, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false, errors.New("invalid IP address")
	}
	if !a.Is4() {
		return netip.Prefix{}, false, errIPv6
	}
	return netip.PrefixFrom(a, 32), false, nil
}

// OverlapsNonPublic reports whether any address of the IPv4 prefix p is non-public — the
// whole range is checked, not just its first address (8.0.0.0/5 starts public but holds 10/8).
func OverlapsNonPublic(p netip.Prefix) bool {
	for _, n := range nonPublicV4 {
		if n.Overlaps(p) {
			return true
		}
	}
	return false
}

// IsNonPublicIP reports whether ip is anything but a public unicast address (see nonPublicV4;
// for IPv6: private, loopback, link-local, multicast or unspecified). Nil is not non-public.
func IsNonPublicIP(ip net.IP) bool {
	if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap().Is4() {
		return OverlapsNonPublic(netip.PrefixFrom(a.Unmap(), 32))
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// WithinRFC1918 reports whether the IPv4 prefix p lies entirely inside one RFC1918 block.
func WithinRFC1918(p netip.Prefix) bool {
	for _, n := range rfc1918 {
		if n.Bits() <= p.Bits() && n.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// RFC1918Ranges returns the RFC1918 blocks as CIDR strings (a fresh slice, safe to append to).
func RFC1918Ranges() []string {
	out := make([]string, len(rfc1918))
	for i, n := range rfc1918 {
		out[i] = n.String()
	}
	return out
}

// FreeUpperHalfIPv4 returns the first free host address in the upper half of cidr, or "" when there
// is none. Virtual IPs and LAN devices' VPN addresses come from there, so they stay visually apart
// from VPN clients (handed out from the low end). Addresses ending in .0 or .255 are skipped: even
// inside a larger prefix some devices and tools refuse them. inUse reports a taken address.
func FreeUpperHalfIPv4(cidr string, inUse func(ip string) bool) string {
	p, isRange, err := ParseIPv4(cidr)
	// Guard the shift/loop math against a pathological mask: real VPN ranges are /16–/30.
	if err != nil || !isRange || p.Bits() < 8 || p.Bits() > 30 {
		return ""
	}
	n := 1 << (32 - p.Bits())
	start := n / 2
	if n < 8 {
		start = 2 // tiny range: scan from the start
	}
	a := p.Addr()
	for i := 0; i < start; i++ {
		a = a.Next()
	}
	for i := start; i < n-1; i, a = i+1, a.Next() {
		if b := a.As4(); b[3] == 0 || b[3] == 255 {
			continue
		}
		if ip := a.String(); !inUse(ip) {
			return ip
		}
	}
	return ""
}
