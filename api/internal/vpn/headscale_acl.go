package vpn

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"api/internal/database"
	"api/internal/helper"
)

// getHeadscaleACLPath returns the configured Headscale ACL path
func getHeadscaleACLPath() string {
	return helper.GetHeadscaleACLPath()
}

// HeadscaleACL represents the Headscale ACL policy file structure
type HeadscaleACL struct {
	Hosts         map[string]string   `json:"hosts"`
	Groups        map[string][]string `json:"groups,omitempty"`
	TagOwners     map[string][]string `json:"tagOwners,omitempty"`
	ACLs          []ACLEntry          `json:"acls"`
	AutoApprovers map[string][]string `json:"autoApprovers,omitempty"`
}

// ACLEntry represents a single ACL entry
type ACLEntry struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

// GenerateAndApplyHeadscaleACL generates Headscale ACL policy from the database and applies it
func GenerateAndApplyHeadscaleACL() error {
	acl, err := generateHeadscaleACL()
	if err != nil {
		return err
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(acl, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Headscale ACL: %v", err)
	}

	aclPath := getHeadscaleACLPath()

	// Ensure directory exists
	os.MkdirAll(filepath.Dir(aclPath), 0755)

	// Write ACL file
	if err := os.WriteFile(aclPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write Headscale ACL: %v", err)
	}

	// Reload Headscale policy via Docker exec
	if err := helper.DockerExec("headscale", []string{"kill", "-HUP", "1"}); err != nil {
		log.Printf("Warning: Could not signal Headscale to reload policy: %v", err)
	}

	log.Printf("Applied Headscale ACL policy")
	return nil
}

func generateHeadscaleACL() (*HeadscaleACL, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}
	wgIPRange := helper.GetEnv("WG_IP_RANGE")

	// Get all clients
	rows, err := db.Query(`SELECT id, name, ip, type, acl_policy FROM vpn_clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type client struct {
		ID     int
		Name   string
		IP     string
		Type   string
		Policy string
	}
	clients := make(map[int]client)

	for rows.Next() {
		var c client
		if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Type, &c.Policy); err != nil {
			continue
		}
		clients[c.ID] = c
	}

	// Get all ACL rules (simplified: source can reach target)
	ruleRows, err := db.Query(`SELECT source_client_id, target_client_id FROM vpn_acl_rules`)
	if err != nil {
		return nil, err
	}
	defer ruleRows.Close()

	type aclRule struct {
		SourceID int
		TargetID int
	}
	var rules []aclRule
	for ruleRows.Next() {
		var r aclRule
		if err := ruleRows.Scan(&r.SourceID, &r.TargetID); err != nil {
			continue
		}
		rules = append(rules, r)
	}

	// Reserved host names that must not be claimed by a client (emitted below).
	routerName := helper.GetEnv("VPN_ROUTER_NAME")
	if routerName == "" {
		routerName = "vpn-router"
	}

	// Assign a STABLE, UNIQUE Headscale host name per client. sanitizeHostName is lossy
	// ("cam 1" and "cam-1" both collapse to "cam-1"), so without this two clients could claim
	// the same name: acl.Hosts would keep only the last (random map order) and an ACL grant
	// could attach to the wrong host. Assign in ID order and suffix any duplicate so every
	// client gets a distinct name that also can't collide with the reserved names.
	used := map[string]bool{"wireguard-network": true, routerName: true}
	names := make(map[int]string, len(clients))
	ids := make([]int, 0, len(clients))
	for id := range clients {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		base := sanitizeHostName(clients[id].Name)
		if base == "" {
			base = fmt.Sprintf("client-%d", id)
		}
		name := base
		for i := 2; used[name]; i++ {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		used[name] = true
		names[id] = name
	}

	// Build Headscale ACL
	acl := &HeadscaleACL{
		Hosts: make(map[string]string),
		ACLs:  []ACLEntry{},
	}

	// Add all clients to hosts
	for id, c := range clients {
		acl.Hosts[names[id]] = c.IP
	}

	// Add WireGuard network as a host entry for routing
	if wgIPRange != "" {
		acl.Hosts["wireguard-network"] = wgIPRange
	}
	acl.ACLs = append(acl.ACLs, ACLEntry{
		Action: "accept",
		Src:    []string{routerName},
		Dst:    []string{"*:*"},
	})
	acl.ACLs = append(acl.ACLs, ACLEntry{
		Action: "accept",
		Src:    []string{"*"},
		Dst:    []string{routerName + ":*"},
	})

	// Track which pairs are already allowed (to avoid duplicates)
	allowedPairs := make(map[string]bool)

	// Handle "allow_all" policies first - these clients can reach everyone
	for _, c := range clients {
		if c.Policy == helper.ACLPolicyAllowAll {
			safeName := names[c.ID]
			// Allow this client to reach everything
			acl.ACLs = append(acl.ACLs, ACLEntry{
				Action: "accept",
				Src:    []string{safeName},
				Dst:    []string{"*:*"},
			})
		}
	}

	// Process explicit rules for "selected" policy clients
	for _, rule := range rules {
		src, srcExists := clients[rule.SourceID]
		dst, dstExists := clients[rule.TargetID]
		if !srcExists || !dstExists {
			continue
		}

		// Skip if source has block_all (isolated, can't reach anyone)
		if src.Policy == helper.ACLPolicyBlockAll {
			continue
		}

		// Skip if target has block_all (isolated, nobody can reach them)
		if dst.Policy == helper.ACLPolicyBlockAll {
			continue
		}

		// Skip if source has allow_all (already covered by wildcard rule above)
		if src.Policy == helper.ACLPolicyAllowAll {
			continue
		}

		srcName := names[src.ID]
		dstName := names[dst.ID]

		key := fmt.Sprintf("%s->%s", srcName, dstName)
		if !allowedPairs[key] {
			acl.ACLs = append(acl.ACLs, ACLEntry{
				Action: "accept",
				Src:    []string{srcName},
				Dst:    []string{dstName + ":*"},
			})
			allowedPairs[key] = true
		}
	}

	// Allow access to wireguard-network via vpn-router for all Headscale clients
	// (except block_all which are isolated)
	for _, c := range clients {
		if c.Type == "headscale" && c.Policy != helper.ACLPolicyBlockAll {
			safeName := names[c.ID]
			acl.ACLs = append(acl.ACLs, ACLEntry{
				Action: "accept",
				Src:    []string{safeName},
				Dst:    []string{"wireguard-network:*"},
			})
		}
	}

	return acl, nil
}

// sanitizeHostName converts a client name to a valid Headscale host name
func sanitizeHostName(name string) string {
	// Replace spaces and special characters with hyphens
	result := ""
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result += string(c)
		} else if c == ' ' {
			result += "-"
		}
	}
	return result
}

// RemoveHeadscaleACL removes the Headscale ACL policy file
func RemoveHeadscaleACL() error {
	// Create a permissive default policy
	defaultACL := &HeadscaleACL{
		Hosts: map[string]string{},
		ACLs: []ACLEntry{
			{
				Action: "accept",
				Src:    []string{"*"},
				Dst:    []string{"*:*"},
			},
		},
	}

	data, err := json.MarshalIndent(defaultACL, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(getHeadscaleACLPath(), data, 0644); err != nil {
		return err
	}

	log.Printf("Reset Headscale ACL to default (allow all)")
	return nil
}
