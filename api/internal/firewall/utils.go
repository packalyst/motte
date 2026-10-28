package firewall

import (
	"fmt"
	"net"
	"strings"
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

// isIgnoredIP checks if an IP should be ignored
func (s *Service) isIgnoredIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if IP is in ignored networks from config
	for _, network := range s.config.IgnoreNetworks {
		if strings.Contains(network, "/") {
			_, ipNet, err := net.ParseCIDR(network)
			if err == nil && ipNet.Contains(parsedIP) {
				return true
			}
		} else {
			if network == ip {
				return true
			}
		}
	}

	// Check for VPN client IPs
	if s.config.WgIPPrefix != "" && strings.HasPrefix(ip, s.config.WgIPPrefix) {
		return true
	}
	if s.config.HeadscaleIPPrefix != "" && strings.HasPrefix(ip, s.config.HeadscaleIPPrefix) {
		return true
	}

	return false
}
