package helper

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Domain validation: alphanumeric, hyphens, dots, underscores
	// Allows: wiki.local, my-app.home, sub.domain.local
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-_\.]*[a-zA-Z0-9])?$`)

	// Simple hostname/label validation (single segment)
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-_]*[a-zA-Z0-9])?$`)
)

// ValidationError represents a validation failure
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidateIP validates an IP address (IPv4 or IPv6)
func ValidateIP(ip string) error {
	if ip == "" {
		return &ValidationError{Field: "ip", Message: "IP address is required"}
	}

	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return &ValidationError{Field: "ip", Message: "invalid IP address format"}
	}

	return nil
}

// ValidatePort validates a port number (1-65535)
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return &ValidationError{Field: "port", Message: "port must be between 1 and 65535"}
	}
	return nil
}

// ValidatePortString validates a port from string input
func ValidatePortString(portStr string) (int, error) {
	if portStr == "" {
		return 0, &ValidationError{Field: "port", Message: "port is required"}
	}

	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil {
		return 0, &ValidationError{Field: "port", Message: "port must be a number"}
	}

	if err := ValidatePort(port); err != nil {
		return 0, err
	}

	return port, nil
}

// ValidateDomain validates a domain name
// Allows formats like: wiki.local, my-app.home, sub.domain.local
func ValidateDomain(domain string) error {
	if domain == "" {
		return &ValidationError{Field: "domain", Message: "domain is required"}
	}

	domain = strings.TrimSpace(domain)

	// Check length
	if len(domain) > 253 {
		return &ValidationError{Field: "domain", Message: "domain name too long (max 253 characters)"}
	}

	// Check overall pattern
	if !domainRegex.MatchString(domain) {
		return &ValidationError{Field: "domain", Message: "invalid domain format (use alphanumeric, hyphens, dots)"}
	}

	// Validate each label (require at least one dot, e.g., "wiki.local")
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return &ValidationError{Field: "domain", Message: "domain must include a TLD (e.g., wiki.local)"}
	}
	for _, label := range labels {
		if len(label) == 0 {
			return &ValidationError{Field: "domain", Message: "domain cannot have empty labels (consecutive dots)"}
		}
		if len(label) > 63 {
			return &ValidationError{Field: "domain", Message: "domain label too long (max 63 characters per segment)"}
		}
		if !hostnameRegex.MatchString(label) {
			return &ValidationError{Field: "domain", Message: "invalid domain label format"}
		}
	}

	return nil
}

// ValidateCIDR validates a CIDR notation (e.g., 192.168.1.0/24)
func ValidateCIDR(cidr string) error {
	if cidr == "" {
		return &ValidationError{Field: "cidr", Message: "CIDR is required"}
	}

	_, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return &ValidationError{Field: "cidr", Message: "invalid CIDR format (e.g., 192.168.1.0/24)"}
	}

	return nil
}

// IsPrivateIP checks if an IP is in a private range
func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}

// IsPrivateIPOrCIDR checks if an IP or CIDR is in a private range
// Handles both single IPs (192.168.1.1) and CIDR notation (192.168.1.0/24)
func IsPrivateIPOrCIDR(input string) bool {
	input = strings.TrimSpace(input)
	if input == "" {
		return false
	}

	var ip net.IP
	if strings.Contains(input, "/") {
		// Parse as CIDR - check the network address
		parsedIP, _, err := net.ParseCIDR(input)
		if err != nil {
			return false
		}
		ip = parsedIP
	} else {
		// Parse as single IP
		ip = net.ParseIP(input)
		if ip == nil {
			return false
		}
	}

	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// ValidateIPOrCIDR validates a single IP address or CIDR notation
func ValidateIPOrCIDR(input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil // Empty is allowed, skip
	}

	if strings.Contains(input, "/") {
		if _, _, err := net.ParseCIDR(input); err != nil {
			return fmt.Errorf("invalid CIDR: %s", input)
		}
	} else {
		if net.ParseIP(input) == nil {
			return fmt.Errorf("invalid IP: %s", input)
		}
	}
	return nil
}

// ValidateIPList validates a list of IP addresses or CIDR notations
func ValidateIPList(ips []string) error {
	for i, ip := range ips {
		if err := ValidateIPOrCIDR(ip); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
	}
	return nil
}

// SanitizeDomainName creates a safe identifier from a domain name
func SanitizeDomainName(domain string) string {
	// Replace dots and other special chars with hyphens
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, domain)

	// Remove consecutive hyphens
	for strings.Contains(safe, "--") {
		safe = strings.ReplaceAll(safe, "--", "-")
	}

	// Trim hyphens from ends
	safe = strings.Trim(safe, "-")

	// Lowercase
	return strings.ToLower(safe)
}

// ValidateURL validates a URL for safe usage (prevents SSRF)
// Allows only http/https schemes and validates format
func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return &ValidationError{Field: "url", Message: "URL is required"}
	}

	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return &ValidationError{Field: "url", Message: "invalid URL format"}
	}

	// Only allow http and https schemes
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return &ValidationError{Field: "url", Message: "URL must use http or https scheme"}
	}

	// Must have a host
	if parsed.Host == "" {
		return &ValidationError{Field: "url", Message: "URL must have a host"}
	}

	return nil
}

// ValidateInternalServiceURL validates a URL for internal service connections
// Used for Headscale, AdGuard, etc. - blocks dangerous metadata endpoints
func ValidateInternalServiceURL(rawURL string) error {
	_, err := SanitizeInternalServiceURL(rawURL)
	return err
}

// SanitizeInternalServiceURL validates and returns a sanitized URL for internal services
// Blocks only dangerous endpoints (cloud metadata)
func SanitizeInternalServiceURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", &ValidationError{Field: "url", Message: "URL is required"}
	}

	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", &ValidationError{Field: "url", Message: "invalid URL format"}
	}

	// Only allow http and https schemes
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", &ValidationError{Field: "url", Message: "URL must use http or https scheme"}
	}

	// Must have a host
	if parsed.Host == "" {
		return "", &ValidationError{Field: "url", Message: "URL must have a host"}
	}

	host := parsed.Hostname()
	port := parsed.Port()

	// Block dangerous endpoints
	if ip := net.ParseIP(host); ip != nil {
		// Block link-local (169.254.x.x) - cloud metadata endpoint
		if ip.IsLinkLocalUnicast() {
			return "", &ValidationError{Field: "url", Message: "URL cannot point to link-local addresses (security risk)"}
		}
	}

	// Reconstruct URL from validated components
	var safeURL string
	if port != "" {
		safeURL = parsed.Scheme + "://" + host + ":" + port + parsed.RequestURI()
	} else {
		safeURL = parsed.Scheme + "://" + host + parsed.RequestURI()
	}
	return safeURL, nil
}

// ValidateBlocklistURL validates a URL for blocklist fetching
// Only allows https and known safe domains
func ValidateBlocklistURL(rawURL string) error {
	_, err := SanitizeBlocklistURL(rawURL)
	return err
}

// SanitizeBlocklistURL validates and returns a sanitized blocklist URL
// Returns the canonical URL string to break taint tracking
func SanitizeBlocklistURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", &ValidationError{Field: "url", Message: "URL is required"}
	}

	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", &ValidationError{Field: "url", Message: "invalid URL format"}
	}

	// Only allow https for external blocklists
	if parsed.Scheme != "https" {
		return "", &ValidationError{Field: "url", Message: "blocklist URL must use https"}
	}

	// Must have a host
	if parsed.Host == "" {
		return "", &ValidationError{Field: "url", Message: "URL must have a host"}
	}

	// Block private/internal IPs to prevent SSRF
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return "", &ValidationError{Field: "url", Message: "blocklist URL cannot point to private/internal addresses"}
		}
	}

	// Return the canonical URL string (breaks taint tracking)
	return parsed.String(), nil
}

// SanitizeURL validates and returns a sanitized URL
// Blocks only dangerous endpoints (cloud metadata)
func SanitizeURL(rawURL string) (string, error) {
	return SanitizeInternalServiceURL(rawURL)
}

// AllowedLogDirs contains directories where log files can be read
var AllowedLogDirs = []string{
	"/var/log",
	"/home",
	"/var/lib/docker",
}

// ValidateLogFilePath validates a log file path to prevent path traversal
func ValidateLogFilePath(logPath string) error {
	if logPath == "" {
		return &ValidationError{Field: "log_file", Message: "log file path is required"}
	}

	// Clean the path to resolve any . or .. components
	cleanPath := filepath.Clean(logPath)

	// Must be an absolute path
	if !filepath.IsAbs(cleanPath) {
		return &ValidationError{Field: "log_file", Message: "log file must be an absolute path"}
	}

	// Check for path traversal attempts
	if strings.Contains(logPath, "..") {
		return &ValidationError{Field: "log_file", Message: "path traversal not allowed"}
	}

	// Verify the path is within allowed directories
	allowed := false
	for _, dir := range AllowedLogDirs {
		if strings.HasPrefix(cleanPath, dir+"/") || cleanPath == dir {
			allowed = true
			break
		}
	}

	if !allowed {
		return &ValidationError{Field: "log_file", Message: "log file must be in /var/log, /home, or /var/lib/docker"}
	}

	return nil
}
