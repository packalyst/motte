package firewall

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

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
	Scope     string `json:"scope"`    // "public" (reachable on the WAN) or "private" (VPN/LAN only)
	Lockable  bool   `json:"lockable"` // false for Docker-published ports — reachability is Docker's, not our set's
}

// handleGetPorts returns allowed ports (from firewall_entries + Docker)
func (s *Service) handleGetPorts(w http.ResponseWriter, r *http.Request) {
	// Get ports from firewall_entries
	rows, err := s.db.Query(`SELECT id, value, protocol, essential, COALESCE(name, ''), source, COALESCE(scope, 'public')
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
		if err := rows.Scan(&p.ID, &portStr, &p.Protocol, &p.Essential, &p.Service, &p.Source, &p.Scope); err != nil {
			continue
		}
		p.Port, _ = strconv.Atoi(portStr)
		p.Lockable = true // a firewall_entries port rides our allow-sets, so the scope toggle is effective
		ports = append(ports, p)
		portMap[fmt.Sprintf("%d-%s", p.Port, p.Protocol)] = true
	}

	// Add Docker exposed ports (mark as essential since they're required for containers). Their
	// reachability is governed by Docker's DNAT path, not our input allow-sets, so the scope toggle
	// would be a no-op — surface them as public + non-lockable so the UI shows a disabled lock.
	dockerPorts := s.getDockerExposedPorts()
	for _, dp := range dockerPorts {
		key := fmt.Sprintf("%d-%s", dp.Port, dp.Protocol)
		if !portMap[key] {
			dp.Scope = "public"
			dp.Lockable = false
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
		router.DBError(w, err)
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

// handleSetPortScope flips an allowed port between 'public' (reachable on the WAN) and 'private'
// (VPN/LAN only). Essential ports are intentionally scopable — hiding admin UIs/DNS from the
// internet is the whole point. Only affects firewall_entries ports; a Docker-published port isn't
// in that table, so it matches 0 rows (its reachability is Docker's, not ours).
func (s *Service) handleSetPortScope(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Scope    string `json:"scope"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "invalid port number (must be 1-65535)", http.StatusBadRequest)
		return
	}
	if req.Scope != "public" && req.Scope != "private" {
		router.JSONError(w, "scope must be 'public' or 'private'", http.StatusBadRequest)
		return
	}
	if req.Protocol == "" {
		req.Protocol = nftables.ProtocolTCP
	}
	res, err := s.db.Exec(`UPDATE firewall_entries SET scope = ?
		WHERE entry_type = 'port' AND action = 'allow' AND value = ? AND protocol = ?`,
		req.Scope, strconv.Itoa(req.Port), req.Protocol)
	if err != nil {
		router.DBError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		router.JSONError(w, "port not in the allow-list (a Docker-published port can't be scoped here)", http.StatusNotFound)
		return
	}
	s.RequestApply()
	router.JSON(w, map[string]interface{}{"port": req.Port, "protocol": req.Protocol, "scope": req.Scope})
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
		router.DBError(w, err)
		return
	}

	s.RequestApply()
	router.JSON(w, map[string]interface{}{"status": "removed", "port": port})
}

// handleChangeSSHPort changes the SSH port
func (s *Service) handleChangeSSHPort(w http.ResponseWriter, r *http.Request) {
	// Step-up: changing the SSH port can lock the operator out of the host.
	if !router.StepUp(w, r) {
		return
	}
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

	newRow := strconv.Itoa(req.Port)
	// undo puts sshd and the firewall back on the old port and reports why.
	undo := func(msg string, restart bool) {
		if _, err := helper.SetSSHPort(oldPort); err != nil {
			log.Printf("Warning: failed to restore sshd_config port %d: %v", oldPort, err)
		}
		if restart {
			if err := helper.RestartSSH(); err != nil {
				log.Printf("Warning: failed to restart SSH on port %d: %v", oldPort, err)
			}
		}
		if _, err := s.db.Exec("DELETE FROM firewall_entries WHERE entry_type = 'port' AND value = ? AND name = 'SSH'", newRow); err != nil {
			log.Printf("Warning: failed to rollback SSH port entry: %v", err)
		}
		s.ApplyRules()
		router.JSONError(w, msg, http.StatusInternalServerError)
	}

	// Update sshd_config
	if _, err = helper.SetSSHPort(req.Port); err != nil {
		undo("failed to update sshd_config: "+err.Error(), false)
		return
	}
	// A Port set in another file (e.g. /etc/ssh/sshd_config.d/) wins: this change wouldn't apply.
	if ports, err := helper.SSHDEffectivePorts(); err == nil && !slices.Contains(ports, req.Port) {
		undo(fmt.Sprintf("SSH's port is set in another config file (sshd uses %v): change it there, e.g. in /etc/ssh/sshd_config.d/", ports), false)
		return
	}
	if err := helper.RestartSSH(); err != nil {
		undo("failed to restart SSH: "+err.Error(), true)
		return
	}
	// The old port is closed only once SSH really listens on the new one.
	listening := false
	for range 20 {
		if helper.HostListensTCP(req.Port) {
			listening = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !listening {
		undo(fmt.Sprintf("SSH didn't start listening on port %d — kept on port %d", req.Port, oldPort), true)
		return
	}

	// Remove the old SSH port from the firewall, unless SSH still listens there too (sshd takes
	// every Port it's given).
	if oldPort != req.Port && !helper.HostListensTCP(oldPort) {
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

// SyncDockerPortsToDB persists Docker-published container ports into
// firewall_entries so they get enforced by nftables (not just shown in the UI).
//
// Behavior:
//   - Disabled entirely if AUTO_DISCOVER_DOCKER_PORTS=false.
//   - At each call, DELETEs every row with source='docker', then re-INSERTs the
//     ports currently published by running containers. That way containers that
//     have stopped drop their allow rules; manually-added rows (source='manual')
//     and system rows (source='system') are never touched.
//   - Uses INSERT OR IGNORE so if a port is already present with a different
//     source (e.g. an essential port that a container happens to publish), the
//     existing row wins and no duplicate is created.
//
// Meant to run once at service init, before ApplyRules.
func (s *Service) SyncDockerPortsToDB() (int, error) {
	if strings.EqualFold(os.Getenv("AUTO_DISCOVER_DOCKER_PORTS"), "false") {
		log.Printf("firewall: AUTO_DISCOVER_DOCKER_PORTS=false, skipping Docker port discovery")
		return 0, nil
	}

	discovered := s.getDockerExposedPorts()

	// Wipe old docker-source rows so ports of removed containers stop being allowed.
	if _, err := s.db.Exec("DELETE FROM firewall_entries WHERE entry_type = 'port' AND source = 'docker'"); err != nil {
		return 0, fmt.Errorf("clear stale docker ports: %w", err)
	}

	inserted := 0
	for _, dp := range discovered {
		if dp.Port < 1 || dp.Port > 65535 {
			continue
		}
		res, err := s.db.Exec(`INSERT OR IGNORE INTO firewall_entries
			(entry_type, value, action, direction, protocol, source, name, essential, enabled)
			VALUES ('port', ?, 'allow', 'inbound', ?, 'docker', ?, 1, 1)`,
			strconv.Itoa(dp.Port), dp.Protocol, dp.Service)
		if err != nil {
			log.Printf("firewall: failed to insert docker port %d/%s: %v", dp.Port, dp.Protocol, err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}

	log.Printf("firewall: docker port sync — %d discovered, %d inserted (rest were already present)", len(discovered), inserted)
	return inserted, nil
}
