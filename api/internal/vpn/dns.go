package vpn

import (
	"fmt"
	"strings"
	"unicode"

	"api/internal/adguard"
	"api/internal/helper"
)

// getVPNDNSSuffix returns the DNS suffix for VPN clients
// Uses HEADSCALE_BASE_DOMAIN to match what Tailscale clients query
func getVPNDNSSuffix() string {
	baseDomain := helper.GetEnvOptional("HEADSCALE_BASE_DOMAIN", "")
	if baseDomain == "" {
		return ""
	}
	return "." + baseDomain
}

// AddClientDNS adds a DNS rewrite for a VPN client. AdGuard's rewrite/add APPENDS (it allows
// multiple answers per domain), so we never add blindly: if the name already resolves to a
// DIFFERENT IP, another device owns it — refuse so the operator renames, rather than stacking
// duplicate answers (wrong-host lookups) or silently stealing the name. Re-adding the same
// name→IP is a no-op.
func AddClientDNS(name, ip string) error {
	suffix := getVPNDNSSuffix()
	if suffix == "" {
		return nil
	}
	domain := sanitizeForDNS(name) + suffix
	if existing, err := adguard.GetRewrites(); err == nil {
		for _, r := range existing {
			if r.Domain != domain {
				continue
			}
			if r.Answer == ip {
				return nil // already set for this client — idempotent
			}
			return fmt.Errorf("DNS name %q is already in use by another device — rename this client", domain)
		}
	}
	return adguard.AddRewrite(domain, ip)
}

// RemoveClientDNS removes a DNS rewrite for a VPN client
func RemoveClientDNS(name, ip string) error {
	suffix := getVPNDNSSuffix()
	if suffix == "" {
		return nil
	}
	domain := sanitizeForDNS(name) + suffix
	return adguard.DeleteRewrite(domain, ip)
}

// HasClientDNS checks if a DNS rewrite exists for a VPN client
func HasClientDNS(name string) bool {
	suffix := getVPNDNSSuffix()
	if suffix == "" {
		return false
	}
	domain := sanitizeForDNS(name) + suffix

	rewrites, err := adguard.GetRewrites()
	if err != nil {
		return false
	}

	for _, r := range rewrites {
		if r.Domain == domain {
			return true
		}
	}
	return false
}

func sanitizeForDNS(name string) string {
	name = strings.ToLower(name)
	var result strings.Builder
	prevDash := false

	for _, c := range name {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			result.WriteRune(c)
			prevDash = false
		} else if c == ' ' || c == '-' || c == '_' {
			if !prevDash && result.Len() > 0 {
				result.WriteRune('-')
				prevDash = true
			}
		}
	}

	s := strings.TrimSuffix(result.String(), "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}
