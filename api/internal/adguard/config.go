package adguard

import (
	"fmt"
	"log"
	"os"
	"strings"

	"api/internal/helper"

	"golang.org/x/crypto/bcrypt"
)

// UpdateCredentials updates the username and password in AdGuardHome.yaml
// Returns true if restart is required (credentials changed)
func UpdateCredentials(configPath, username, password string) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}

	newContent := updateYAMLUser(content, username, string(hashedPassword))

	if newContent == content {
		return false, nil // No changes needed
	}

	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return false, err
	}

	log.Printf("Updated AdGuard config with new credentials for user: %s", username)
	return true, nil
}

// updateYAMLUser updates the first user entry in the YAML content
func updateYAMLUser(content, username, hashedPassword string) string {
	newContent, err := helper.UpdateYAMLPaths(content, []helper.YAMLUpdate{
		{Path: "users.0.name", Value: username},
		{Path: "users.0.password", Value: hashedPassword},
	})
	if err != nil {
		log.Printf("Warning: failed to update YAML: %v", err)
		return content
	}
	return newContent
}

// UpdateDashboard updates the http.address in AdGuardHome.yaml
// enabled=true: 0.0.0.0:port (accessible externally)
// enabled=false: 127.0.0.1:port (local only)
func UpdateDashboard(configPath string, enabled bool) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	content := string(data)

	// Get current address to extract port
	port := "8083"
	if addr, err := helper.GetYAMLPath(content, "http.address"); err == nil {
		if addrStr, ok := addr.(string); ok {
			parts := strings.Split(addrStr, ":")
			if len(parts) >= 2 {
				port = parts[len(parts)-1]
			}
		}
	}

	var newAddress string
	if enabled {
		newAddress = "0.0.0.0:" + port
	} else {
		newAddress = "127.0.0.1:" + port
	}

	newContent, err := helper.UpdateYAMLPath(content, "http.address", newAddress)
	if err != nil {
		return fmt.Errorf("failed to update YAML: %v", err)
	}

	return os.WriteFile(configPath, []byte(newContent), 0644)
}

// UpdateQuerylogSize updates the querylog.size_memory in AdGuardHome.yaml
func UpdateQuerylogSize(configPath string, size int) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	newContent, err := helper.UpdateYAMLPath(string(data), "querylog.size_memory", size)
	if err != nil {
		return fmt.Errorf("failed to update YAML: %v", err)
	}

	return os.WriteFile(configPath, []byte(newContent), 0644)
}
