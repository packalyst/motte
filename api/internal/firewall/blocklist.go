package firewall

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"api/internal/helper"
)

// Blocklist sources loaded from config file
var blocklistSources map[string]BlocklistSource

func init() {
	blocklistSources = make(map[string]BlocklistSource)
}

// LoadBlocklistSources loads blocklist sources from JSON file
func LoadBlocklistSources() {
	configPath := os.Getenv("BLOCKLIST_CONFIG_PATH")
	if configPath == "" {
		configPath = helper.BlocklistSourcesPath
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Warning: failed to load blocklist sources from %s: %v", configPath, err)
		return
	}

	if err := json.Unmarshal(data, &blocklistSources); err != nil {
		log.Printf("Warning: failed to parse blocklist sources: %v", err)
		return
	}

	log.Printf("Loaded %d blocklist sources from config", len(blocklistSources))
}

// fetchBlocklist fetches and parses a blocklist from URL
func (s *Service) fetchBlocklist(rawURL string, minScore int) ([]string, error) {
	// Validate and sanitize URL to prevent SSRF
	sanitizedURL, err := helper.SanitizeURL(rawURL)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(sanitizedURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{resp.StatusCode}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseBlocklistBody(string(body), minScore), nil
}

// parseBlocklistBody parses blocklist content into IP/CIDR entries
func parseBlocklistBody(body string, minScore int) []string {
	var entries []string
	lines := strings.Split(body, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Handle ipsum format (IP\tSCORE)
		if strings.Contains(line, "\t") {
			parts := strings.Split(line, "\t")
			if len(parts) >= 2 {
				ip := strings.TrimSpace(parts[0])
				score, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
				if minScore > 0 && score < minScore {
					continue
				}
				entries = append(entries, ip)
				continue
			}
		}

		// Skip lines with spaces (likely comments or descriptions)
		if strings.Contains(line, " ") {
			continue
		}

		entries = append(entries, line)
	}

	return entries
}

// httpError is a simple error type for HTTP errors
type httpError struct {
	StatusCode int
}

func (e *httpError) Error() string {
	return "HTTP " + strconv.Itoa(e.StatusCode)
}
