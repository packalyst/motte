package vpn

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/database"
	"api/internal/domains"
	"api/internal/helper"
	"api/internal/nftables"
	"api/internal/router"
	"api/internal/settings"
	"api/internal/wireguard"
	"api/internal/ws"
)

// syncClient upserts a VPN client into the database
func syncClient(db *sql.DB, existing map[string]int, seen map[string]bool,
	name, ip, clientType, externalID, rawData string, added *int) {
	seen[ip] = true
	if id, exists := existing[ip]; exists {
		db.Exec(`UPDATE vpn_clients SET name = ?, raw_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			name, rawData, id)
	} else {
		_, err := db.Exec(`INSERT INTO vpn_clients (name, ip, type, external_id, raw_data, acl_policy) VALUES (?, ?, ?, ?, ?, ?)`,
			name, ip, clientType, externalID, rawData, helper.DefaultACLPolicy)
		if err == nil {
			*added++
		}
	}
}

// GetNodeStats returns current VPN node statistics from the database
func GetNodeStats() ws.NodeStats {
	db, err := database.GetDB()
	if err != nil {
		return ws.NodeStats{}
	}

	var stats ws.NodeStats

	rows, err := db.Query(`SELECT type, raw_data FROM vpn_clients`)
	if err != nil {
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var clientType string
		var rawData []byte
		if err := rows.Scan(&clientType, &rawData); err != nil {
			continue
		}

		switch clientType {
		case "headscale":
			stats.HsNodes++
		case "wireguard":
			stats.WgPeers++
		}

		if len(rawData) > 0 && isNodeOnline(rawData) {
			stats.Online++
		} else {
			stats.Offline++
		}
	}

	return stats
}

// isNodeOnline checks if the raw JSON data indicates the node is online
func isNodeOnline(rawData []byte) bool {
	// Simple byte scan for "online":true pattern
	// More efficient than full JSON parsing
	for i := 0; i < len(rawData)-12; i++ {
		if rawData[i] == '"' && rawData[i+1] == 'o' && rawData[i+2] == 'n' &&
			rawData[i+3] == 'l' && rawData[i+4] == 'i' && rawData[i+5] == 'n' &&
			rawData[i+6] == 'e' && rawData[i+7] == '"' && rawData[i+8] == ':' {
			// Found "online":, check for true
			j := i + 9
			for j < len(rawData) && rawData[j] == ' ' {
				j++
			}
			if j+4 <= len(rawData) && rawData[j] == 't' && rawData[j+1] == 'r' &&
				rawData[j+2] == 'u' && rawData[j+3] == 'e' {
				return true
			}
		}
	}
	return false
}

// Service handles unified VPN client management and ACL
type Service struct {
	wgIPRange string
	hsIPRange string
}

// VPNClient represents a unified view of a VPN client (WireGuard or Headscale)
type VPNClient struct {
	ID         int             `json:"id"`
	Name       string          `json:"name"`
	IP         string          `json:"ip"`
	Type       string          `json:"type"` // "wireguard" or "headscale"
	ExternalID string          `json:"externalId,omitempty"`
	RawData    json.RawMessage `json:"rawData,omitempty"` // Full data from source system
	ACLPolicy  string          `json:"aclPolicy"`         // block_all, selected, allow_all
	TotalTx    int64           `json:"totalTx"`           // Total bytes transmitted
	TotalRx    int64           `json:"totalRx"`           // Total bytes received
	CreatedAt  time.Time       `json:"createdAt"`
	UpdatedAt  time.Time       `json:"updatedAt"`
	// Enriched fields (not stored in DB)
	AllowedCount int `json:"allowedCount,omitempty"`
}

// ACLRule represents an ACL rule between two clients
type ACLRule struct {
	ID             int       `json:"id"`
	SourceClientID int       `json:"sourceClientId"`
	TargetClientID int       `json:"targetClientId"`
	Bidirectional  bool      `json:"bidirectional"`
	CreatedAt      time.Time `json:"createdAt"`
}

// ACLClientView represents how a client appears in the ACL list
type ACLClientView struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Type      string `json:"type"`
	Policy    string `json:"aclPolicy"`
	IsEnabled bool   `json:"isEnabled"` // Can current client reach this one
	IsBi      bool   `json:"isBi"`      // Is relationship bidirectional
}

// ClientACLUpdate is the request body for updating a client's ACL
type ClientACLUpdate struct {
	Policy        string       `json:"policy"`
	AllowedRules  []ACLRuleReq `json:"rules"` // New format: list of rules with bi flag
}

// ACLRuleReq is a single rule in the update request
type ACLRuleReq struct {
	TargetID      int  `json:"targetId"`
	Bidirectional bool `json:"bidirectional"`
}

// New creates a new VPN service
func New() *Service {
	wgRange := helper.GetEnv("WG_IP_RANGE")
	hsRange := helper.GetEnv("HEADSCALE_IP_RANGE")

	log.Printf("VPN service initialized (WG: %s, HS: %s)", wgRange, hsRange)
	return &Service{
		wgIPRange: wgRange,
		hsIPRange: hsRange,
	}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		// Clients & ACL
		"GetClients":  s.handleGetClients,
		"GetClient":   s.handleGetClient,
		"UpdateACL":   s.handleUpdateACL,
		"ApplyRules":  s.handleApplyRules,
		"ToggleDNS":   s.handleToggleDNS,
		// Port Scanner
		"ScanPorts": s.handleScanPorts,
		"StopScan":  s.handleStopScan,
		// Router Management
		"GetRouterStatus": s.handleGetRouterStatus,
		"SetupRouter":     s.handleSetupRouter,
		"RestartRouter":   s.handleRestartRouter,
		"RemoveRouter":    s.handleRemoveRouter,
	}
}

// --- Client Handlers ---

func (s *Service) handleGetClients(w http.ResponseWriter, r *http.Request) {
	// Auto-sync to get fresh data from WireGuard and Headscale
	s.SyncClients()

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Use LEFT JOIN with subquery to avoid N+1 query problem
	rows, err := db.Query(`
		SELECT c.id, c.name, c.ip, c.type, c.external_id, c.raw_data,
		       c.acl_policy, c.total_tx, c.total_rx, c.created_at, c.updated_at,
		       COALESCE(counts.cnt, 0) as allowed_count
		FROM vpn_clients c
		LEFT JOIN (
			SELECT source_client_id, COUNT(*) as cnt
			FROM vpn_acl_rules
			GROUP BY source_client_id
		) counts ON c.id = counts.source_client_id
		ORDER BY c.type, c.name
	`)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	clients := []VPNClient{}
	for rows.Next() {
		var c VPNClient
		var externalID, rawData sql.NullString
		if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Type, &externalID, &rawData, &c.ACLPolicy, &c.TotalTx, &c.TotalRx, &c.CreatedAt, &c.UpdatedAt, &c.AllowedCount); err != nil {
			continue
		}
		c.ExternalID = database.StringFromNull(externalID, "")
		if rawData.Valid {
			c.RawData = json.RawMessage(rawData.String)
		}
		clients = append(clients, c)
	}

	router.JSON(w, clients)
}

func (s *Service) handleGetClient(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/vpn/clients/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var c VPNClient
	var externalID sql.NullString
	err = db.QueryRow(`
		SELECT id, name, ip, type, external_id, acl_policy, total_tx, total_rx, created_at, updated_at
		FROM vpn_clients WHERE id = ?
	`, id).Scan(&c.ID, &c.Name, &c.IP, &c.Type, &externalID, &c.ACLPolicy, &c.TotalTx, &c.TotalRx, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		router.JSONError(w, "client not found", http.StatusNotFound)
		return
	}
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.ExternalID = database.StringFromNull(externalID, "")

	// Get ACL view for this client (all other clients with enabled/bi state)
	aclView := s.getClientACLView(c.ID)

	router.JSON(w, map[string]interface{}{
		"client":  c,
		"aclView": aclView,
		"hasDNS":  HasClientDNS(c.Name),
	})
}

func (s *Service) handleToggleDNS(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/vpn/clients/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		router.JSONError(w, "invalid client ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var name, ip string
	err = db.QueryRow(`SELECT name, ip FROM vpn_clients WHERE id = ?`, id).Scan(&name, &ip)
	if err != nil {
		router.JSONError(w, "client not found", http.StatusNotFound)
		return
	}

	if req.Enabled {
		err = AddClientDNS(name, ip)
	} else {
		err = RemoveClientDNS(name, ip)
	}

	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]bool{"enabled": req.Enabled})
}

func (s *Service) handleUpdateACL(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path like /api/vpn/clients/123/acl
	path := strings.TrimPrefix(r.URL.Path, "/api/vpn/clients/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	viewerID, err := strconv.Atoi(parts[0])
	if err != nil {
		router.JSONError(w, "invalid client ID", http.StatusBadRequest)
		return
	}

	var req ClientACLUpdate
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if !helper.IsValidACLPolicy(req.Policy) {
		router.JSONError(w, "invalid policy", http.StatusBadRequest)
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Update client policy
	if _, err = tx.Exec(`UPDATE vpn_clients SET acl_policy = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, req.Policy, viewerID); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Handle policy-specific logic
	switch req.Policy {
	case helper.ACLPolicyBlockAll:
		// Isolated: delete all rules involving this client
		if _, err = tx.Exec(`DELETE FROM vpn_acl_rules WHERE source_client_id = ? OR target_client_id = ?`, viewerID, viewerID); err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case helper.ACLPolicyAllowAll:
		// Can reach everyone: delete rules where viewer is source (blanket rule covers it)
		// Keep rules where viewer is target (others explicitly allowed viewer)
		if _, err = tx.Exec(`DELETE FROM vpn_acl_rules WHERE source_client_id = ?`, viewerID); err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case helper.ACLPolicySelected:
		// Apply state machine for each rule
		if err := s.applyACLRules(tx, viewerID, req.AllowedRules); err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]string{"status": "ok"})
}

// applyACLRules implements the ACL state machine
// One entry per client pair - handles enable/disable/bidirectional transitions
func (s *Service) applyACLRules(tx *sql.Tx, viewerID int, desiredRules []ACLRuleReq) error {
	// Build desired state map: targetID -> (enabled, bi)
	desired := make(map[int]ACLRuleReq)
	for _, r := range desiredRules {
		if r.TargetID != viewerID {
			desired[r.TargetID] = r
		}
	}

	// Get current rules involving viewer
	rows, err := tx.Query(`
		SELECT id, source_client_id, target_client_id, bidirectional
		FROM vpn_acl_rules
		WHERE source_client_id = ? OR target_client_id = ?
	`, viewerID, viewerID)
	if err != nil {
		return err
	}

	type currentRule struct {
		id       int
		srcID    int
		tgtID    int
		bi       bool
		otherID  int
		isSrc    bool // viewer is source
	}
	var current []currentRule
	for rows.Next() {
		var r currentRule
		if err := rows.Scan(&r.id, &r.srcID, &r.tgtID, &r.bi); err != nil {
			rows.Close()
			return err
		}
		if r.srcID == viewerID {
			r.otherID = r.tgtID
			r.isSrc = true
		} else {
			r.otherID = r.srcID
			r.isSrc = false
		}
		current = append(current, r)
	}
	rows.Close()

	// Build current state map
	currentMap := make(map[int]currentRule)
	for _, r := range current {
		currentMap[r.otherID] = r
	}

	// Process each desired rule
	for targetID, want := range desired {
		cur, exists := currentMap[targetID]

		if !exists {
			// No entry exists - INSERT new rule
			if _, err := tx.Exec(`INSERT INTO vpn_acl_rules (source_client_id, target_client_id, bidirectional) VALUES (?, ?, ?)`,
				viewerID, targetID, want.Bidirectional); err != nil {
				return err
			}
		} else if cur.isSrc {
			// Viewer is source: (viewer, target, bi)
			if cur.bi != want.Bidirectional {
				// Update bi flag
				if _, err := tx.Exec(`UPDATE vpn_acl_rules SET bidirectional = ? WHERE id = ?`, want.Bidirectional, cur.id); err != nil {
					return err
				}
			}
		} else {
			// Viewer is target: (target, viewer, bi)
			if want.Bidirectional && !cur.bi {
				// Want bi, currently not bi: set bi=true
				if _, err := tx.Exec(`UPDATE vpn_acl_rules SET bidirectional = 1 WHERE id = ?`, cur.id); err != nil {
					return err
				}
			} else if !want.Bidirectional && cur.bi {
				// Want no bi, currently bi: swap direction to (viewer, target, bi=false)
				if _, err := tx.Exec(`UPDATE vpn_acl_rules SET source_client_id = ?, target_client_id = ?, bidirectional = 0 WHERE id = ?`,
					viewerID, targetID, cur.id); err != nil {
					return err
				}
			} else if !want.Bidirectional && !cur.bi {
				// Other has one-way to viewer, viewer wants one-way to other: set bi=true
				if _, err := tx.Exec(`UPDATE vpn_acl_rules SET bidirectional = 1 WHERE id = ?`, cur.id); err != nil {
					return err
				}
			}
		}
		delete(currentMap, targetID)
	}

	// Remove rules for clients no longer in desired list
	for _, cur := range currentMap {
		if cur.isSrc {
			// Viewer was source, now disabled
			if cur.bi {
				// bi=true: reverse to keep other→viewer direction
				if _, err := tx.Exec(`UPDATE vpn_acl_rules SET source_client_id = ?, target_client_id = ?, bidirectional = 0 WHERE id = ?`,
					cur.tgtID, viewerID, cur.id); err != nil {
					return err
				}
			} else {
				// bi=false: just delete
				if _, err := tx.Exec(`DELETE FROM vpn_acl_rules WHERE id = ?`, cur.id); err != nil {
					return err
				}
			}
		} else {
			// Viewer was target - other client had enabled viewer
			if cur.bi {
				// bi=true: viewer was allowing reverse, now removing - set bi=false
				if _, err := tx.Exec(`UPDATE vpn_acl_rules SET bidirectional = 0 WHERE id = ?`, cur.id); err != nil {
					return err
				}
			}
			// bi=false: viewer can't unilaterally delete other's rule, just remove bi access
		}
	}

	return nil
}

func (s *Service) handleApplyRules(w http.ResponseWriter, r *http.Request) {
	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]string{"status": "ok"})
}

// --- Router Handlers ---

func (s *Service) handleGetRouterStatus(w http.ResponseWriter, r *http.Request) {
	status := GetRouterStatus()
	router.JSON(w, status)
}

func (s *Service) handleSetupRouter(w http.ResponseWriter, r *http.Request) {
	if err := SetupRouter(); err != nil {
		log.Printf("Router setup error: %v", err)
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "starting"})
}

func (s *Service) handleRestartRouter(w http.ResponseWriter, r *http.Request) {
	if err := RestartRouter(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "ok"})
}

func (s *Service) handleRemoveRouter(w http.ResponseWriter, r *http.Request) {
	if err := RemoveRouter(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "ok"})
}

// --- Helper Methods ---

// getClientACLView returns how each client appears in the ACL list for the given viewer
func (s *Service) getClientACLView(viewerID int) []ACLClientView {
	db, err := database.GetDB()
	if err != nil {
		return nil
	}

	// Get all clients except the viewer
	rows, err := db.Query(`
		SELECT c.id, c.name, c.ip, c.type, c.acl_policy
		FROM vpn_clients c
		WHERE c.id != ?
		ORDER BY c.type, c.name
	`, viewerID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var clients []ACLClientView
	for rows.Next() {
		var c ACLClientView
		if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Type, &c.Policy); err != nil {
			continue
		}
		clients = append(clients, c)
	}

	// Get all rules involving the viewer (as source or target)
	ruleRows, err := db.Query(`
		SELECT source_client_id, target_client_id, bidirectional
		FROM vpn_acl_rules
		WHERE source_client_id = ? OR target_client_id = ?
	`, viewerID, viewerID)
	if err != nil {
		return clients
	}
	defer ruleRows.Close()

	// Build lookup: for each other client, determine enabled/bi state
	type ruleInfo struct {
		isSource bool // viewer is source
		bi       bool
	}
	ruleLookup := make(map[int]ruleInfo) // otherClientID -> info

	for ruleRows.Next() {
		var srcID, tgtID int
		var bi bool
		if err := ruleRows.Scan(&srcID, &tgtID, &bi); err != nil {
			continue
		}
		if srcID == viewerID {
			// Viewer is source: can reach target
			ruleLookup[tgtID] = ruleInfo{isSource: true, bi: bi}
		} else {
			// Viewer is target: other client can reach viewer
			// Viewer can reach other only if bi=true
			ruleLookup[srcID] = ruleInfo{isSource: false, bi: bi}
		}
	}

	// Apply rule info to clients
	for i := range clients {
		if info, exists := ruleLookup[clients[i].ID]; exists {
			if info.isSource {
				// Viewer→Client: enabled
				clients[i].IsEnabled = true
				clients[i].IsBi = info.bi
			} else if info.bi {
				// Client→Viewer with bi: enabled (bi allows reverse)
				clients[i].IsEnabled = true
				clients[i].IsBi = true
			}
			// Client→Viewer without bi: not enabled for viewer
		}
	}

	return clients
}

// SyncClients synchronizes VPN clients from WireGuard and Headscale
func (s *Service) SyncClients() (added int, removed int, err error) {
	db, err := database.GetDB()
	if err != nil {
		return 0, 0, err
	}

	// Get existing clients
	existing := make(map[string]int) // ip -> id
	rows, err := db.Query(`SELECT id, ip FROM vpn_clients`)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var id int
		var ip string
		if err := rows.Scan(&id, &ip); err != nil {
			continue
		}
		existing[ip] = id
	}
	rows.Close()

	seen := make(map[string]bool)

	// Sync WireGuard peers with full data
	wgSvc := wireguard.GetService()
	if wgSvc != nil {
		peers := wgSvc.ListPeersWithStatus()
		for _, peer := range peers {
			// Strip sensitive keys before storing in database
			peerCopy := *peer
			peerCopy.PrivateKey = ""
			peerCopy.PresharedKey = ""
			rawData, _ := json.Marshal(peerCopy)
			syncClient(db, existing, seen, peer.Name, peer.IPAddress, "wireguard", peer.ID, string(rawData), &added)
		}
	}

	// Sync Headscale nodes with full data
	hsNodes, rawNodes, err := s.getHeadscaleNodesWithRaw()
	if err != nil {
		log.Printf("Warning: failed to get Headscale nodes: %v", err)
	} else {
		routerName := helper.GetEnvOptional("VPN_ROUTER_NAME", "vpn-router")
		for i, node := range hsNodes {
			// Skip router node
			if node.Name == routerName {
				continue
			}
			syncClient(db, existing, seen, node.Name, node.IP, "headscale", node.ID, rawNodes[i], &added)
		}
	}

	// Remove stale clients (no longer in WireGuard or Headscale)
	for ip, id := range existing {
		if !seen[ip] {
			// Delete domain routes for this client first
			domains.DeleteClientRoutes(id)
			// ACL rules are automatically deleted via ON DELETE CASCADE
			_, err := db.Exec(`DELETE FROM vpn_clients WHERE id = ?`, id)
			if err == nil {
				removed++
			}
		}
	}

	// Broadcast node stats update if anything changed
	if added > 0 || removed > 0 {
		ws.BroadcastNodeStats()
	}

	return added, removed, nil
}

type hsNode struct {
	ID   string
	Name string
	IP   string
}

// getHeadscaleNodesWithRaw returns nodes along with their raw JSON data
func (s *Service) getHeadscaleNodesWithRaw() ([]hsNode, []string, error) {
	resp, err := helper.HeadscaleGet("/node")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("failed to get Headscale nodes: %s", string(body))
	}

	var result struct {
		Nodes []json.RawMessage `json:"nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, err
	}

	nodes := make([]hsNode, 0, len(result.Nodes))
	rawNodes := make([]string, 0, len(result.Nodes))

	for _, rawNode := range result.Nodes {
		var n struct {
			ID        string   `json:"id"`
			Name      string   `json:"name"`
			GivenName string   `json:"givenName"`
			IPAddrs   []string `json:"ipAddresses"`
		}
		if err := json.Unmarshal(rawNode, &n); err != nil {
			continue
		}

		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		ip := ""
		for _, addr := range n.IPAddrs {
			// Prefer IPv4
			if !strings.Contains(addr, ":") {
				ip = addr
				break
			}
		}
		if ip == "" && len(n.IPAddrs) > 0 {
			ip = n.IPAddrs[0]
		}
		nodes = append(nodes, hsNode{ID: n.ID, Name: name, IP: ip})
		rawNodes = append(rawNodes, string(rawNode))
	}
	return nodes, rawNodes, nil
}

// ApplyRules triggers nftables apply and generates Headscale ACL
func (s *Service) ApplyRules() error {
	// Request nftables apply (debounced, applies all registered tables including VPN ACL)
	if nftSvc := nftables.GetService(); nftSvc != nil {
		nftSvc.RequestApply()
	}

	// Generate and apply Headscale ACL
	if err := GenerateAndApplyHeadscaleACL(); err != nil {
		return fmt.Errorf("failed to apply Headscale ACL: %v", err)
	}

	return nil
}

// --- Port Scanner ---

// ScanRequest for POST /api/vpn/clients/{id}/scan
type ScanRequest struct {
	Mode string `json:"mode"` // "common", "range", "full"
}

// ScanProgress represents port scan progress sent via WebSocket
type ScanProgress struct {
	Event     string              `json:"event"`
	ClientID  string              `json:"clientId"`
	IP        string              `json:"ip"`
	Mode      string              `json:"mode"`
	Total     int                 `json:"total"`
	Scanned   int                 `json:"scanned"`
	Found     int                 `json:"found"`
	Completed bool                `json:"completed"`
	Stopped   bool                `json:"stopped,omitempty"`
	Ports     []helper.PortResult `json:"ports,omitempty"`
	Error     string              `json:"error,omitempty"`
}

// activeScan tracks a running scan
type activeScan struct {
	cancel context.CancelFunc
}

// activeScans tracks running scans by clientID
var activeScans = make(map[string]*activeScan)
var activeScansMu = &sync.Mutex{}

// extractScanClientID extracts client ID from scan endpoint paths
func extractScanClientID(r *http.Request) (string, bool) {
	path := strings.TrimPrefix(r.URL.Path, "/api/vpn/clients/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "scan" {
		return "", false
	}
	return parts[0], true
}

func (s *Service) handleScanPorts(w http.ResponseWriter, r *http.Request) {
	clientID, ok := extractScanClientID(r)
	if !ok {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Check if scan already running for this client
	activeScansMu.Lock()
	if _, exists := activeScans[clientID]; exists {
		activeScansMu.Unlock()
		router.JSONError(w, "scan already running for this client", http.StatusConflict)
		return
	}
	activeScansMu.Unlock()

	// Get client IP from database
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var clientIP string
	err = db.QueryRow("SELECT ip FROM vpn_clients WHERE id = ?", clientID).Scan(&clientIP)
	if err == sql.ErrNoRows {
		router.JSONError(w, "client not found", http.StatusNotFound)
		return
	}
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse request
	var req ScanRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if req.Mode == "" {
		req.Mode = "common"
	}

	// Validate mode
	if req.Mode != "common" && req.Mode != "range" && req.Mode != "full" {
		router.JSONError(w, "invalid mode: use 'common', 'range', or 'full'", http.StatusBadRequest)
		return
	}

	// Get scanner settings
	config := helper.ScanConfig{
		PortStart:  settings.GetSettingInt("scanner_port_start", 1),
		PortEnd:    settings.GetSettingInt("scanner_port_end", 5000),
		Concurrent: settings.GetSettingInt("scanner_concurrent", 100),
		PauseMs:    settings.GetSettingInt("scanner_pause_ms", 0),
		TimeoutMs:  settings.GetSettingInt("scanner_timeout_ms", 500),
	}

	// Return immediately - scan runs in background
	router.JSON(w, map[string]interface{}{
		"status":   "started",
		"clientId": clientID,
		"ip":       clientIP,
		"mode":     req.Mode,
	})

	// Run scan in goroutine with progress via WebSocket
	go runScanWithProgress(clientID, clientIP, req.Mode, config)
}

// handleStopScan stops a running scan for a client
func (s *Service) handleStopScan(w http.ResponseWriter, r *http.Request) {
	clientID, ok := extractScanClientID(r)
	if !ok {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}

	activeScansMu.Lock()
	scan, exists := activeScans[clientID]
	if exists {
		// Remove immediately so new scan can start
		delete(activeScans, clientID)
	}
	activeScansMu.Unlock()

	if !exists {
		router.JSONError(w, "no active scan for this client", http.StatusNotFound)
		return
	}

	// Cancel the scan - goroutine will clean up and send final results
	scan.cancel()

	router.JSON(w, map[string]interface{}{
		"status":   "stopped",
		"clientId": clientID,
	})
}

// runScanWithProgress runs a port scan and broadcasts progress via WebSocket
func runScanWithProgress(clientID, clientIP, mode string, config helper.ScanConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), helper.PortScanTimeout)

	// Track results for live updates
	var results []helper.PortResult
	var resultsMu sync.Mutex
	var lastTotal, lastScanned int

	// Register active scan
	activeScansMu.Lock()
	activeScans[clientID] = &activeScan{cancel: cancel}
	activeScansMu.Unlock()

	// Cleanup - safe to call multiple times
	defer func() {
		cancel()
		activeScansMu.Lock()
		delete(activeScans, clientID)
		activeScansMu.Unlock()
	}()

	// Helper to broadcast scan progress
	broadcast := func(event string, total, scanned int, completed, stopped bool, err string) {
		resultsMu.Lock()
		ports := make([]helper.PortResult, len(results))
		copy(ports, results)
		resultsMu.Unlock()

		msg := ScanProgress{
			Event:     event,
			ClientID:  clientID,
			IP:        clientIP,
			Mode:      mode,
			Total:     total,
			Scanned:   scanned,
			Found:     len(ports),
			Completed: completed,
			Stopped:   stopped,
			Ports:     ports,
			Error:     err,
		}
		ws.Broadcast("general_info", msg)
	}

	// Channels for scan updates
	progressChan := make(chan helper.ScanProgress, 100)
	portFoundChan := make(chan helper.PortResult, 100)

	// Collect found ports
	go func() {
		for port := range portFoundChan {
			resultsMu.Lock()
			results = append(results, port)
			resultsMu.Unlock()
		}
	}()

	// Broadcast progress with throttling
	go func() {
		lastBroadcast := time.Now()
		lastPortCount := 0
		for progress := range progressChan {
			if progress.Completed {
				continue // Final message sent separately
			}

			// Track total/scanned for final broadcast
			lastTotal = progress.Total
			lastScanned = progress.Scanned

			resultsMu.Lock()
			portCount := len(results)
			resultsMu.Unlock()

			// Broadcast if throttle passed OR new ports found
			if time.Since(lastBroadcast) >= 100*time.Millisecond || portCount > lastPortCount {
				broadcast("scan:progress", progress.Total, progress.Scanned, false, false, "")
				lastBroadcast = time.Now()
				lastPortCount = portCount
			}
		}
	}()

	// Run scan
	var scanErr error
	switch mode {
	case "common":
		_, scanErr = helper.ScanCommonPorts(ctx, clientIP, config, progressChan, portFoundChan)
	case "range":
		_, scanErr = helper.ScanRange(ctx, clientIP, config.PortStart, config.PortEnd, config, progressChan, portFoundChan)
	case "full":
		_, scanErr = helper.ScanFull(ctx, clientIP, config, progressChan, portFoundChan)
	}

	close(portFoundChan)
	close(progressChan)

	// Determine final state
	stopped := ctx.Err() == context.Canceled
	errMsg := ""
	if scanErr != nil && !stopped {
		errMsg = scanErr.Error()
	}

	broadcast("scan:complete", lastTotal, lastScanned, true, stopped, errMsg)
}
