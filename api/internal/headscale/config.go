package headscale

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"api/internal/helper"
)

// TestURL checks if headscale is reachable at the given public URL
func TestURL(publicURL string) error {
	baseURL := strings.TrimSuffix(publicURL, "/")
	// SSRF-guard: the URL is admin-supplied; block link-local/cloud-metadata on every hop
	// (RFC1918/loopback stay reachable — headscale is typically internal).
	client := helper.SafeInternalHTTPClient(10 * time.Second)

	// Try /key endpoint (public, returns noise key)
	resp, err := client.Get(baseURL + "/key")
	if err != nil {
		return fmt.Errorf("cannot reach headscale at %s: %w", publicURL, err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("headscale not responding at %s (status %d)", publicURL, resp.StatusCode)
	}

	return nil
}

// UpdateConfig updates server_url and derp.server.hostname in config.yaml
func UpdateConfig(configPath, serverURL string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	content := string(data)

	// Extract hostname from URL (e.g., "https://ee.bitbot.ro" -> "ee.bitbot.ro")
	hostname := serverURL
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	hostname = strings.TrimSuffix(hostname, "/")

	// Update server_url and derp.server.hostname
	newContent, err := helper.UpdateYAMLPaths(content, []helper.YAMLUpdate{
		{Path: "server_url", Value: serverURL},
		{Path: "derp.server.hostname", Value: hostname},
	})
	if err != nil {
		return fmt.Errorf("failed to update YAML: %w", err)
	}

	if newContent == content {
		return nil // No changes needed
	}

	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	log.Printf("Updated Headscale config: server_url=%s, hostname=%s", serverURL, hostname)
	return nil
}
