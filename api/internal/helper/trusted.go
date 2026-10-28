package helper

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// Trusted networks: who may open the panel in VPN-only mode (the sentinel_vpn allow-list) and who
// the firewall jails never ban. The VPN ranges are always in and can't be removed (locked), so the
// list is never empty; the admin's extras are edited in Settings and seeded from IGNORE_NETWORKS.

var (
	trustedMu     sync.RWMutex
	trustedExtras []string
)

// minTrustedPrefix is the widest extra range accepted: 0.0.0.0/1 would trust half the internet
// (VPN-only off for them, never auto-banned).
const minTrustedPrefix = 8

// vpnPrefixes parses the VPN ranges (WG_IP_RANGE, HEADSCALE_IP_RANGE) — the one definition of
// "the VPN" every feature reads. An unset or invalid range is skipped.
func vpnPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, env := range []string{"WG_IP_RANGE", "HEADSCALE_IP_RANGE"} {
		if p, isRange, err := ParseIPv4(GetEnvOptional(env, "")); err == nil && isRange && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// VPNRanges returns the VPN ranges as CIDR strings. They are always in the trusted list (locked).
func VPNRanges() []string {
	var out []string
	for _, p := range vpnPrefixes() {
		out = append(out, p.String())
	}
	return out
}

// IsVPNIP reports whether ip is a WireGuard or Headscale client address.
func IsVPNIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	for _, p := range vpnPrefixes() {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// TrustedNetworks returns the full trusted list: the locked VPN ranges first, then the extras.
func TrustedNetworks() []string {
	trustedMu.RLock()
	defer trustedMu.RUnlock()
	return append(VPNRanges(), trustedExtras...)
}

// TrustedExtras returns the admin's extras (a copy).
func TrustedExtras() []string {
	trustedMu.RLock()
	defer trustedMu.RUnlock()
	return slices.Clone(trustedExtras)
}

// SetTrustedExtras replaces the in-memory extras. Pass a list from TrustedExtrasFrom.
func SetTrustedExtras(extras []string) {
	trustedMu.Lock()
	defer trustedMu.Unlock()
	trustedExtras = slices.Clone(extras)
}

// TrustedExtrasFrom validates a submitted trusted list (IPs or CIDRs, IPv4 or IPv6) and returns
// the extras in canonical form: the locked VPN ranges and duplicates are dropped, since the
// locked ranges are always in anyway. Anything malformed or wider than /8 is an error.
func TrustedExtrasFrom(list []string) ([]string, error) {
	locked := VPNRanges()
	var out []string
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		v, err := canonicalNet(item)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(locked, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

// canonicalNet normalizes an IP or CIDR (1.2.3.4/24 → 1.2.3.0/24).
func canonicalNet(s string) (string, error) {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return "", fmt.Errorf("invalid IP: %s", s)
		}
		return ip.String(), nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %s", s)
	}
	if ones, _ := n.Mask.Size(); ones < minTrustedPrefix {
		return "", fmt.Errorf("%s is too broad: ranges wider than /%d are not allowed", s, minTrustedPrefix)
	}
	return n.String(), nil
}

// IsTrustedIP reports whether ip is inside the trusted list.
func IsTrustedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range TrustedNetworks() { // canonical: a CIDR or a bare IP
		if _, ipNet, err := net.ParseCIDR(n); err == nil {
			if ipNet.Contains(ip) {
				return true
			}
		} else if net.ParseIP(n).Equal(ip) {
			return true
		}
	}
	return false
}
