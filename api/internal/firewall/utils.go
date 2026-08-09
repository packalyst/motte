package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"api/internal/helper"
)

// validateIPOrCIDR validates an IP address or CIDR range
func validateIPOrCIDR(input string) (string, bool, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", false, fmt.Errorf("empty input")
	}

	// Check if it's a CIDR range
	if strings.Contains(input, "/") {
		_, ipNet, err := net.ParseCIDR(input)
		if err != nil {
			return "", false, fmt.Errorf("invalid CIDR: %v", err)
		}
		// Reject IPv6: the nftables blocked sets are ipv4_addr, so an IPv6 element
		// would be rejected by the kernel and break the atomic ruleset reload. This
		// panel is IPv4-only and drops external IPv6 wholesale at the firewall, so
		// per-address IPv6 blocking is neither possible nor needed here.
		if ipNet.IP.To4() == nil {
			return "", false, fmt.Errorf("IPv6 is not supported (this panel is IPv4-only; external IPv6 is dropped at the firewall)")
		}
		return ipNet.String(), true, nil
	}

	// Check if it's a single IP
	ip := net.ParseIP(input)
	if ip == nil {
		return "", false, fmt.Errorf("invalid IP address")
	}

	// Reject IPv6 (see CIDR branch above).
	if ip.To4() == nil {
		return "", false, fmt.Errorf("IPv6 is not supported (this panel is IPv4-only; external IPv6 is dropped at the firewall)")
	}
	return ip.To4().String(), false, nil
}

// isIPv4Value reports whether input is an IPv4 address or IPv4 CIDR. Used to keep
// non-IPv4 values out of the ipv4_addr nftables sets: an IPv6 element there would be
// rejected by the kernel and break the atomic ruleset reload. This guards the
// automated auto-block path, where the value comes from log lines rather than a
// human-validated form (an attacker's real IP via CF-Connecting-IP can be IPv6).
func isIPv4Value(input string) bool {
	input = strings.TrimSpace(input)
	if strings.Contains(input, "/") {
		_, ipNet, err := net.ParseCIDR(input)
		return err == nil && ipNet.IP.To4() != nil
	}
	ip := net.ParseIP(input)
	return ip != nil && ip.To4() != nil
}

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

// isPrivateRange checks if an IP or CIDR is in private IP space
// Uses helper.IsPrivateIPOrCIDR for consistent behavior across packages
func isPrivateRange(input string) bool {
	return helper.IsPrivateIPOrCIDR(input)
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

// isPrivateIP checks if an IP is in private ranges
func (s *Service) isPrivateIP(ip string) bool {
	return isPrivateRange(ip)
}

// reverseDNS performs a reverse DNS lookup with caching
func (s *Service) reverseDNS(ip string) string {
	// Check cache first
	if domain, found := s.dnsCache.get(ip); found {
		return domain
	}

	// Do reverse lookup with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.DNSLookupTimeout)*time.Second)
	defer cancel()

	var domain string
	done := make(chan struct{})
	go func() {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			domain = strings.TrimSuffix(names[0], ".")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		domain = ""
	}

	// Cache the result (even empty ones to avoid repeated lookups)
	s.dnsCache.set(ip, domain)
	return domain
}
