package firewall

import (
	"fmt"
	"net"

	"api/internal/helper"
)

// getSubnet24 returns the /24 subnet for an IP
func getSubnet24(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if ip4 := parsed.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
	}
	return ""
}

// isIgnoredIP reports whether a jail must never count or ban ip: a trusted network (the VPN
// ranges and the admin's extras, see helper.TrustedNetworks) or any other non-public address
// (LANs, loopback — the same set blockLockoutError refuses to ban).
func (s *Service) isIgnoredIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (helper.IsTrustedIP(p) || helper.IsNonPublicIP(p))
}
