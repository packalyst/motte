package nftables

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Valid patterns for nftables identifiers and values
var (
	validIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	validSetType    = regexp.MustCompile(`^(ipv4_addr|ipv6_addr|ether_addr|inet_proto|inet_service|mark|ifname)$`)
	validFamily     = regexp.MustCompile(`^(ip|ip6|inet|arp|bridge|netdev)$`)
	validPolicy     = regexp.MustCompile(`^(accept|drop)$`)
	validChainType  = regexp.MustCompile(`^(filter|nat|route)$`)
	validHook       = regexp.MustCompile(`^(prerouting|input|forward|output|postrouting|ingress|egress)$`)
	validFlag       = regexp.MustCompile(`^(constant|interval|timeout|dynamic)$`)
)

// ValidateIdentifier checks if a string is a valid nftables identifier
func ValidateIdentifier(s string) bool {
	return validIdentifier.MatchString(s) && len(s) <= 64
}

// ValidateIPOrCIDR checks if a string is a valid IP address or CIDR
func ValidateIPOrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Try parsing as CIDR
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	// Try parsing as IP
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	return false
}

// ValidateIPv4OrCIDR is like ValidateIPOrCIDR but rejects IPv6. The firewall and vpn_acl
// tables emit IPv4-only matchers (ip saddr/daddr) and ipv4_addr sets, so an IPv6 address
// reaching a rule produces invalid nftables and — because the table is applied atomically
// (delete + recreate in one script) — wedges the ENTIRE table, silently dropping all its
// rules (for vpn_acl that flips peer isolation from default-deny to default-allow). Every
// address that flows into a rule must pass this, so a stray IPv6 value is skipped, never emitted.
func ValidateIPv4OrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip.To4() != nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil
	}
	return false
}

// SanitizeElement sanitizes a set element (IP, port, etc.)
func SanitizeElement(s string) string {
	// Remove any characters that could break nftables syntax
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, ";", "")
	s = strings.ReplaceAll(s, "{", "")
	s = strings.ReplaceAll(s, "}", "")
	s = strings.ReplaceAll(s, "#", "")
	return s
}

// BuildSet generates an nftables set definition
func BuildSet(name, setType string, flags []string, elements []string) string {
	// Validate name
	if !ValidateIdentifier(name) {
		name = "invalid_set"
	}
	// Validate set type
	if !validSetType.MatchString(setType) {
		setType = "ipv4_addr"
	}

	// "auto-merge" is NOT a `flags` keyword — it's a standalone set statement, and it
	// requires `flags interval`. Pull it out of the flags slice, emit the real flags,
	// then emit `auto-merge` on its own line. Without auto-merge, nft rejects a set with
	// overlapping interval elements and wedges the whole atomic reload.
	autoMerge := false
	validFlags := make([]string, 0, len(flags))
	hasInterval := false
	for _, f := range flags {
		if f == "auto-merge" {
			autoMerge = true
			continue
		}
		if validFlag.MatchString(f) {
			validFlags = append(validFlags, f)
			if f == "interval" {
				hasInterval = true
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("    set %s {\n", name))
	sb.WriteString(fmt.Sprintf("        type %s\n", setType))

	if len(validFlags) > 0 {
		sb.WriteString(fmt.Sprintf("        flags %s\n", strings.Join(validFlags, ", ")))
	}
	// Only valid alongside `flags interval`; guard so we never emit it on a plain set.
	if autoMerge && hasInterval {
		sb.WriteString("        auto-merge\n")
	}

	if len(elements) > 0 {
		// Sanitize each element
		sanitized := make([]string, 0, len(elements))
		for _, e := range elements {
			s := SanitizeElement(e)
			if s != "" {
				sanitized = append(sanitized, s)
			}
		}
		if len(sanitized) > 0 {
			sb.WriteString("        elements = { ")
			sb.WriteString(strings.Join(sanitized, ", "))
			sb.WriteString(" }\n")
		}
	}

	sb.WriteString("    }\n")
	return sb.String()
}

// BuildChain generates an nftables chain definition
func BuildChain(name, chainType, hook string, priority int, policy string, rules []string) string {
	// Validate inputs
	if !ValidateIdentifier(name) {
		name = "invalid_chain"
	}
	if !validChainType.MatchString(chainType) {
		chainType = "filter"
	}
	if !validHook.MatchString(hook) {
		hook = "input"
	}
	if !validPolicy.MatchString(policy) {
		policy = "drop"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("    chain %s {\n", name))
	sb.WriteString(fmt.Sprintf("        type %s hook %s priority %d; policy %s;\n\n", chainType, hook, priority, policy))

	for _, rule := range rules {
		// Sanitize rules - remove dangerous characters
		rule = strings.ReplaceAll(rule, "\n", " ")
		rule = strings.ReplaceAll(rule, "\r", "")
		sb.WriteString(fmt.Sprintf("        %s\n", rule))
	}

	sb.WriteString("    }\n")
	return sb.String()
}

// TableHeader returns the table header
func TableHeader(family, name string) string {
	// Validate family
	if !validFamily.MatchString(family) {
		family = "inet"
	}
	// Validate table name
	if !ValidateIdentifier(name) {
		name = "invalid_table"
	}
	return fmt.Sprintf(`#!/usr/sbin/nft -f

table %s %s {
`, family, name)
}

// TableFooter returns the table closing brace
func TableFooter() string {
	return "}\n"
}

// SanitizeComment removes characters that break nftables comments
func SanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "#", "")
	s = strings.ReplaceAll(s, "\"", "'")
	return s
}

// ParseSetElementCount parses nftables output to count set elements
func ParseSetElementCount(output, setName string) int {
	lines := strings.Split(output, "\n")
	inSet := false
	inElements := false
	count := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "set "+setName+" {") {
			inSet = true
			inElements = false
			continue
		}

		if inSet && trimmed == "}" {
			inSet = false
			inElements = false
			continue
		}

		if inSet && strings.HasPrefix(trimmed, "elements = {") {
			inElements = true
		}

		if inElements {
			for _, part := range strings.Split(trimmed, ",") {
				part = strings.TrimSpace(part)
				part = strings.TrimSuffix(part, "}")
				part = strings.TrimPrefix(part, "elements = {")
				part = strings.TrimSpace(part)
				if part != "" {
					count++
				}
			}
		}

		if inElements && strings.HasSuffix(trimmed, "}") && !strings.HasPrefix(trimmed, "set ") {
			inElements = false
		}
	}

	return count
}
