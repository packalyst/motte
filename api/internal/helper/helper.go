package helper

import (
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

// TurbotunnelsAuthLogPath is the api-owned file the turbotunnels proxy's auth
// failures are mirrored to and that the 'turbotunnels' firewall jail monitors.
// It lives under DATA_DIR (writable) because /var/log is read-only in the api
// container. Defined here so both the turbotunnels writer and the firewall jail
// agree on the path without an import cycle.
func TurbotunnelsAuthLogPath() string {
	return GetEnvOptional("DATA_DIR", "/data") + "/turbotunnels-auth.log"
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

// SessionToken returns the caller's session token: from the HttpOnly session cookie (set
// after login) when present, otherwise from an Authorization: Bearer header (for non-browser
// API clients). The cookie path is CSRF-guarded by the router's same-origin check together
// with the cookie's SameSite=Strict attribute; the Bearer path carries no ambient authority
// and is therefore exempt from that check.
func SessionToken(r *http.Request) string {
	if v := sessionCookieValue(r); v != "" {
		return v
	}
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
//  1. Every port the host's SSH server listens on (SSHPorts — always).
//  2. Ports listed in a JSON file — either at ESSENTIAL_PORTS_FILE (env
//     override) or at DefaultEssentialPortsFile. Missing/unreadable/invalid
//     JSON is a warning, not fatal — Docker discovery still runs later.
//
// Duplicates (same port+protocol) are collapsed; SSH always wins for that slot.
func BuildEssentialPorts() []EssentialPort {
	ports := []EssentialPort{}

	for _, sshPort := range SSHPorts() {
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

	oldPort := GetSSHPort()
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
