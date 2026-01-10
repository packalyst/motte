package helper

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// GetEnv returns the value of an environment variable or fatally exits if not set
func GetEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("FATAL: Required environment variable %s is not set", key)
	}
	return v
}

// GetEnvOptional returns the value of an environment variable or the default if not set
func GetEnvOptional(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// GetEnvInt returns the integer value of an environment variable or fatally exits if not set
func GetEnvInt(key string) int {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("FATAL: Required environment variable %s is not set", key)
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("FATAL: Environment variable %s must be an integer, got: %s", key, v)
	}
	return i
}

// GetEnvIntOptional returns the integer value of an environment variable or the default if not set
func GetEnvIntOptional(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

// ParsePortList parses a comma-separated list of ports (e.g., "22,80,443")
func ParsePortList(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if port, err := strconv.Atoi(p); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

// ParseStringList parses a comma-separated list of strings
func ParseStringList(s string) []string {
	var items []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

// ExtractIPPrefix extracts the first two octets from a CIDR (e.g., "100.65.0.0/16" -> "100.65.")
func ExtractIPPrefix(cidr string) string {
	parts := strings.Split(cidr, "/")
	if len(parts) < 1 {
		return ""
	}
	ip := parts[0]
	octets := strings.Split(ip, ".")
	if len(octets) >= 2 {
		return octets[0] + "." + octets[1] + "."
	}
	return ""
}

// ExtractBearerToken extracts the Bearer token from Authorization header or cookie
func ExtractBearerToken(r *http.Request) string {
	// Check Authorization header first
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Check cookie
	if cookie, err := r.Cookie("session_token"); err == nil {
		return cookie.Value
	}

	return ""
}

// EssentialPort represents a port with its service name
type EssentialPort struct {
	Port     int
	Protocol string
	Service  string
}

// BuildEssentialPorts builds the list of essential ports from environment variables
func BuildEssentialPorts() []EssentialPort {
	ports := []EssentialPort{}

	// Auto-detect SSH port from sshd_config
	sshPort := detectSSHPort()
	if sshPort > 0 {
		ports = append(ports, EssentialPort{Port: sshPort, Protocol: "tcp", Service: "SSH"})
	}

	// Build from env vars
	portMappings := []struct {
		envVar   string
		service  string
		protocol string
	}{
		{"HTTP_PORT", "Traefik HTTP", "tcp"},
		{"HTTPS_PORT", "Traefik HTTPS", "tcp"},
		{"WG_PORT", "WireGuard", "udp"},
		{"TRAEFIK_PORT", "Traefik Dashboard", "tcp"},
		{"API_PORT", "API", "tcp"},
		{"ADGUARD_PORT", "AdGuard", "tcp"},
		{"STUN_PORT", "STUN/DERP", "udp"},
		{"DNS_PORT", "DNS", "udp"},
		{"HEADSCALE_METRICS_PORT", "Headscale Metrics", "tcp"},
		{"HEADSCALE_GRPC_PORT", "Headscale gRPC", "tcp"},
	}

	for _, mapping := range portMappings {
		if portStr := os.Getenv(mapping.envVar); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
				// Avoid duplicates (e.g., if SSH is on port 22 and something else too)
				exists := false
				for _, p := range ports {
					if p.Port == port && p.Protocol == mapping.protocol {
						exists = true
						break
					}
				}
				if !exists {
					ports = append(ports, EssentialPort{Port: port, Protocol: mapping.protocol, Service: mapping.service})
				}
			}
		}
	}

	return ports
}

// GetSSHPort reads the SSH port from sshd_config (exported version)
func GetSSHPort() int {
	return detectSSHPort()
}

// detectSSHPort reads the SSH port from sshd_config
func detectSSHPort() int {
	// Try common sshd_config locations
	paths := SSHConfigPaths

	for _, path := range paths {
		port := readSSHPortFromFile(path)
		if port > 0 {
			return port
		}
	}

	// Default SSH port
	return 22
}

// readSSHPortFromFile reads SSH port from a single config file
func readSSHPortFromFile(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Look for Port directive
		if strings.HasPrefix(line, "Port ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if port, err := strconv.Atoi(parts[1]); err == nil {
					return port
				}
			}
		}
	}
	return 0
}

// SetSSHPort updates the SSH port in sshd_config
// Returns the old port that was configured
func SetSSHPort(newPort int) (int, error) {
	configPath := SSHConfigPaths[0] // Use primary SSH config path

	// Read current config
	content, err := os.ReadFile(configPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read sshd_config: %w", err)
	}

	oldPort := detectSSHPort()
	lines := strings.Split(string(content), "\n")
	var newLines []string
	portFound := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for existing Port directive (not commented)
		if strings.HasPrefix(trimmed, "Port ") {
			newLines = append(newLines, fmt.Sprintf("Port %d", newPort))
			portFound = true
			continue
		}

		// Check for commented Port directive - uncomment and set new port
		if strings.HasPrefix(trimmed, "#Port ") && !portFound {
			newLines = append(newLines, fmt.Sprintf("Port %d", newPort))
			portFound = true
			continue
		}

		newLines = append(newLines, line)
	}

	// If no Port directive found, add one after the first comment block
	if !portFound {
		var finalLines []string
		inserted := false
		for i, line := range newLines {
			finalLines = append(finalLines, line)
			// Insert after initial comments, before first real directive
			if !inserted && i > 0 && !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.TrimSpace(line) != "" {
				// Insert before this line
				finalLines = finalLines[:len(finalLines)-1]
				finalLines = append(finalLines, fmt.Sprintf("Port %d", newPort))
				finalLines = append(finalLines, line)
				inserted = true
			}
		}
		if !inserted {
			// Just append at the beginning after any initial comments
			finalLines = append([]string{fmt.Sprintf("Port %d", newPort)}, newLines...)
		}
		newLines = finalLines
	}

	// Write back
	newContent := strings.Join(newLines, "\n")
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return oldPort, fmt.Errorf("failed to write sshd_config: %w", err)
	}

	return oldPort, nil
}
