package firewall

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"api/internal/helper"
	"api/internal/nftables"
	"api/internal/router"
)

// PortEntry represents an allowed port for API response
type PortEntry struct {
	ID        int64  `json:"id,omitempty"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Essential bool   `json:"essential"`
	Service   string `json:"service,omitempty"`
	Source    string `json:"source,omitempty"`
}

// handleGetPorts returns allowed ports (from firewall_entries + Docker)
func (s *Service) handleGetPorts(w http.ResponseWriter, r *http.Request) {
	// Get ports from firewall_entries
	rows, err := s.db.Query(`SELECT id, value, protocol, essential, COALESCE(name, ''), source
		FROM firewall_entries WHERE entry_type = 'port' AND action = 'allow' AND enabled = 1
		ORDER BY CAST(value AS INTEGER)`)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	ports := []PortEntry{}
	portMap := make(map[string]bool) // key: "port-protocol"

	for rows.Next() {
		var p PortEntry
		var portStr string
		if err := rows.Scan(&p.ID, &portStr, &p.Protocol, &p.Essential, &p.Service, &p.Source); err != nil {
			continue
		}
		p.Port, _ = strconv.Atoi(portStr)
		ports = append(ports, p)
		portMap[fmt.Sprintf("%d-%s", p.Port, p.Protocol)] = true
	}

	// Add Docker exposed ports (mark as essential since they're required for containers)
	dockerPorts := s.getDockerExposedPorts()
	for _, dp := range dockerPorts {
		key := fmt.Sprintf("%d-%s", dp.Port, dp.Protocol)
		if !portMap[key] {
			ports = append(ports, dp)
		}
	}

	router.JSON(w, ports)
}

// handleAddPort adds an allowed port
func (s *Service) handleAddPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "invalid port number (must be 1-65535)", http.StatusBadRequest)
		return
	}

	if req.Protocol == "" {
		req.Protocol = nftables.ProtocolTCP
	}

	// Check if it's an essential port
	isEssential := false
	for _, ep := range s.config.EssentialPorts {
		if req.Port == ep.Port && req.Protocol == ep.Protocol {
			isEssential = true
			if req.Service == "" {
				req.Service = ep.Service
			}
			break
		}
	}

	_, err := s.db.Exec(`INSERT INTO firewall_entries
		(entry_type, value, action, direction, protocol, source, name, essential, enabled)
		VALUES ('port', ?, 'allow', 'inbound', ?, 'manual', ?, ?, 1)
		ON CONFLICT(entry_type, value, protocol) DO UPDATE SET
		name = excluded.name, enabled = 1`,
		strconv.Itoa(req.Port), req.Protocol, req.Service, isEssential)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.RequestApply()
	router.JSON(w, map[string]interface{}{
		"port":      req.Port,
		"protocol":  req.Protocol,
		"essential": isEssential,
		"service":   req.Service,
	})
}

// handleRemovePort removes an allowed port
func (s *Service) handleRemovePort(w http.ResponseWriter, r *http.Request) {
	portStr := router.ExtractPathParam(r, "/api/fw/ports/")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		router.JSONError(w, "invalid port", http.StatusBadRequest)
		return
	}

	// Check if essential
	var essential bool
	err = s.db.QueryRow("SELECT essential FROM firewall_entries WHERE entry_type = 'port' AND value = ?", portStr).Scan(&essential)
	if err == nil && essential {
		router.JSONError(w, "cannot remove essential port", http.StatusForbidden)
		return
	}

	_, err = s.db.Exec("DELETE FROM firewall_entries WHERE entry_type = 'port' AND value = ? AND essential = 0", portStr)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.RequestApply()
	router.JSON(w, map[string]interface{}{"status": "removed", "port": port})
}

// handleChangeSSHPort changes the SSH port
func (s *Service) handleChangeSSHPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port int `json:"port"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "invalid port number (must be 1-65535)", http.StatusBadRequest)
		return
	}

	if req.Port < 1024 && req.Port != 22 {
		log.Printf("Warning: changing SSH to privileged port %d", req.Port)
	}

	oldPort := helper.GetSSHPort()
	if oldPort == req.Port {
		router.JSON(w, map[string]interface{}{
			"status":  "unchanged",
			"port":    req.Port,
			"message": "SSH is already on this port",
		})
		return
	}

	// Add new port to firewall as essential
	_, err := s.db.Exec(`INSERT INTO firewall_entries
		(entry_type, value, action, direction, protocol, source, name, essential, enabled)
		VALUES ('port', ?, 'allow', 'inbound', 'tcp', 'system', 'SSH', 1, 1)
		ON CONFLICT(entry_type, value, protocol) DO UPDATE SET
		name = 'SSH', essential = 1, enabled = 1`,
		strconv.Itoa(req.Port))
	if err != nil {
		router.JSONError(w, "failed to add new port to firewall: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, "failed to apply firewall rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update sshd_config
	_, err = helper.SetSSHPort(req.Port)
	if err != nil {
		if _, delErr := s.db.Exec("DELETE FROM firewall_entries WHERE entry_type = 'port' AND value = ? AND name = 'SSH'", strconv.Itoa(req.Port)); delErr != nil {
			log.Printf("Warning: failed to rollback SSH port entry: %v", delErr)
		}
		s.ApplyRules()
		router.JSONError(w, "failed to update sshd_config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Restart SSH service
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "restart", "sshd")
	if _, err := cmd.CombinedOutput(); err != nil {
		cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "restart", "ssh")
		if _, err2 := cmd.CombinedOutput(); err2 != nil {
			helper.SetSSHPort(oldPort)
			if _, delErr := s.db.Exec("DELETE FROM firewall_entries WHERE entry_type = 'port' AND value = ? AND name = 'SSH'", strconv.Itoa(req.Port)); delErr != nil {
				log.Printf("Warning: failed to rollback SSH port entry: %v", delErr)
			}
			s.ApplyRules()
			router.JSONError(w, "failed to restart SSH", http.StatusInternalServerError)
			return
		}
	}

	// Remove old SSH port from firewall
	if oldPort != req.Port {
		if _, err := s.db.Exec("DELETE FROM firewall_entries WHERE entry_type = 'port' AND value = ? AND name = 'SSH'", strconv.Itoa(oldPort)); err != nil {
			log.Printf("Warning: failed to delete old SSH port entry: %v", err)
		}
		s.config.EssentialPorts = helper.BuildEssentialPorts()
		s.ApplyRules()
	}

	// Update sshd jail
	if _, err := s.db.Exec("UPDATE jails SET port = ? WHERE name = 'sshd'", strconv.Itoa(req.Port)); err != nil {
		log.Printf("Warning: failed to update sshd jail port: %v", err)
	}

	router.JSON(w, map[string]interface{}{
		"status":  "success",
		"oldPort": oldPort,
		"newPort": req.Port,
		"message": fmt.Sprintf("SSH port changed from %d to %d", oldPort, req.Port),
	})
}

// getDockerExposedPorts returns ports exposed by Docker containers
func (s *Service) getDockerExposedPorts() []PortEntry {
	client := helper.NewDockerHTTPClientWithTimeout(helper.DockerQuickTimeout)

	req, err := http.NewRequest("GET", "http://docker/v1.44/containers/json", nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var rawContainers []struct {
		Names []string
		Ports []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawContainers); err != nil {
		return nil
	}

	portMap := make(map[string]PortEntry)

	for _, c := range rawContainers {
		containerName := ""
		if len(c.Names) > 0 {
			containerName = strings.TrimPrefix(c.Names[0], "/")
		}

		for _, p := range c.Ports {
			if p.PublicPort > 0 && (p.IP == "" || p.IP == "0.0.0.0" || p.IP == "::") {
				key := fmt.Sprintf("%d-%s", p.PublicPort, p.Type)
				if _, exists := portMap[key]; !exists {
					portMap[key] = PortEntry{
						Port:      p.PublicPort,
						Protocol:  p.Type,
						Essential: true,
						Service:   fmt.Sprintf("Docker: %s", containerName),
						Source:    "docker",
					}
				}
			}
		}
	}

	ports := []PortEntry{}
	for _, p := range portMap {
		ports = append(ports, p)
	}

	return ports
}
