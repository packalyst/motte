package helper

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// DefaultEssentialPortsFile is where BuildEssentialPorts looks for the port
// list when ESSENTIAL_PORTS_FILE is not set. Ships in the api docker image.
const DefaultEssentialPortsFile = "/app/configs/essential-ports.json"

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
	// Only accept the token from the Authorization header. We deliberately do
	// NOT read it from a cookie: cookies are auto-attached by the browser on
	// cross-site requests (CSRF), whereas a Bearer header is not. The UI sends
	// the token from localStorage as a Bearer header, and the WebSocket
	// authenticates via its first message, so no cookie path is needed.
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

// EssentialPort represents a port with its service name
type EssentialPort struct {
	Port     int
	Protocol string
	Service  string
}

// essentialPortJSON is the on-disk shape of a port entry in essential-ports.json.
type essentialPortJSON struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
}

// BuildEssentialPorts builds the list of essential ports at boot time.
//
// Sources, in order:
//  1. SSH port auto-detected from sshd_config (always).
//  2. Ports listed in a JSON file — either at ESSENTIAL_PORTS_FILE (env
//     override) or at DefaultEssentialPortsFile. Missing/unreadable/invalid
//     JSON is a warning, not fatal — Docker discovery still runs later.
//
// Duplicates (same port+protocol) are collapsed; SSH always wins for that slot.
func BuildEssentialPorts() []EssentialPort {
	ports := []EssentialPort{}

	if sshPort := detectSSHPort(); sshPort > 0 {
		ports = append(ports, EssentialPort{Port: sshPort, Protocol: "tcp", Service: "SSH"})
	}

	path := GetEnvOptional("ESSENTIAL_PORTS_FILE", DefaultEssentialPortsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("essential-ports: %s not found, skipping (Docker discovery still runs)", path)
		} else {
			log.Printf("essential-ports: cannot read %s: %v (skipping)", path, err)
		}
		return ports
	}

	var entries []essentialPortJSON
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("essential-ports: invalid JSON in %s: %v (skipping)", path, err)
		return ports
	}

	for _, e := range entries {
		if e.Port < 1 || e.Port > 65535 {
			log.Printf("essential-ports: skipping invalid port %d in %s", e.Port, path)
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(e.Proto))
		if proto != "tcp" && proto != "udp" && proto != "both" {
			log.Printf("essential-ports: skipping port %d — invalid proto %q in %s", e.Port, e.Proto, path)
			continue
		}
		// Skip duplicates (SSH auto-detect already added, or JSON lists same port twice).
		dup := false
		for _, p := range ports {
			if p.Port == e.Port && p.Protocol == proto {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		ports = append(ports, EssentialPort{Port: e.Port, Protocol: proto, Service: strings.TrimSpace(e.Service)})
	}

	log.Printf("essential-ports: loaded %d entries from %s", len(entries), path)
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

// ParseUserAgent extracts a readable device/browser name from User-Agent string
func ParseUserAgent(ua string) string {
	if ua == "" {
		return "Unknown device"
	}

	ua = strings.ToLower(ua)

	// Check for mobile devices first
	if strings.Contains(ua, "iphone") {
		return "iPhone"
	}
	if strings.Contains(ua, "ipad") {
		return "iPad"
	}
	if strings.Contains(ua, "android") {
		if strings.Contains(ua, "mobile") {
			return "Android Phone"
		}
		return "Android Tablet"
	}

	// Check for desktop browsers
	if strings.Contains(ua, "firefox") {
		return "Firefox"
	}
	if strings.Contains(ua, "edg/") {
		return "Edge"
	}
	if strings.Contains(ua, "chrome") {
		return "Chrome"
	}
	if strings.Contains(ua, "safari") {
		return "Safari"
	}

	// Check for OS
	if strings.Contains(ua, "windows") {
		return "Windows"
	}
	if strings.Contains(ua, "mac os") {
		return "Mac"
	}
	if strings.Contains(ua, "linux") {
		return "Linux"
	}

	return "Unknown device"
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
