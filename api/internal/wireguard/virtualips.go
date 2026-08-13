package wireguard

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"api/internal/database"
	"api/internal/router"
)

// VirtualIP is an extra VPN /32 routed to a peer and mapped to a LAN device by a
// DNAT on that peer. When Restricted, only AllowedClientIDs may reach it (enforced
// on the server's forward chain by vpn_acl).
type VirtualIP struct {
	ID               int64   `json:"id"`
	IP               string  `json:"ip"`
	Label            string  `json:"label"`
	Restricted       bool    `json:"restricted"`
	AllowedClientIDs []int64 `json:"allowedClientIds"`
}

// clientIDForPeerIP returns the vpn_clients.id for a wireguard peer's VPN IP.
func clientIDForPeerIP(ip string) (int64, error) {
	db, err := database.GetDB()
	if err != nil {
		return 0, fmt.Errorf("database unavailable")
	}
	var id int64
	if err := db.QueryRow(`SELECT id FROM vpn_clients WHERE ip = ? AND type = 'wireguard'`, ip).Scan(&id); err != nil {
		return 0, fmt.Errorf("peer not found in client table")
	}
	return id, nil
}

// validateVirtualIP verifies ipStr is a usable virtual IP and returns it normalized.
// It must be a valid IPv4 inside the WireGuard range, not the server IP, and not
// already used by a peer or another virtual IP.
func (s *Service) validateVirtualIP(ipStr string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("virtual IP must be a valid IPv4 address")
	}
	v4 := ip.To4()
	norm := v4.String()

	_, ipNet, err := net.ParseCIDR(s.config.IPRange)
	if err != nil || !ipNet.Contains(v4) {
		return "", fmt.Errorf("virtual IP must be inside the WireGuard range %s", s.config.IPRange)
	}
	if norm == s.config.ServerIP {
		return "", fmt.Errorf("virtual IP cannot be the server IP")
	}

	db, err := database.GetDB()
	if err != nil {
		return "", fmt.Errorf("database unavailable")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vpn_clients WHERE ip = ?`, norm).Scan(&n); err == nil && n > 0 {
		return "", fmt.Errorf("%s is already assigned to a peer", norm)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM vpn_virtual_ips WHERE ip = ?`, norm).Scan(&n); err == nil && n > 0 {
		return "", fmt.Errorf("%s is already a virtual IP", norm)
	}
	return norm, nil
}

// loadVIPAllowed returns the source client IDs allowed to reach a virtual IP.
func loadVIPAllowed(vipID int64) []int64 {
	ids := []int64{}
	db, err := database.GetDB()
	if err != nil {
		return ids
	}
	rows, err := db.Query(`SELECT source_client_id FROM vpn_virtual_ip_acl WHERE virtual_ip_id = ?`, vipID)
	if err != nil {
		return ids
	}
	defer rows.Close()
	for rows.Next() {
		var cid int64
		if rows.Scan(&cid) == nil {
			ids = append(ids, cid)
		}
	}
	return ids
}

// handleAddVirtualIP  POST /api/wg/peers/{id}/vips
func (s *Service) handleAddVirtualIP(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	var req struct {
		IP         string `json:"ip"`
		Label      string `json:"label"`
		Restricted *bool  `json:"restricted"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	vip, err := s.validateVirtualIP(req.IP)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(req.Label)
	if len(label) > 64 {
		label = label[:64]
	}
	restricted := 1 // secure default: reachable by no one until peers are opted in
	if req.Restricted != nil && !*req.Restricted {
		restricted = 0
	}

	clientID, err := clientIDForPeerIP(peer.IPAddress)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	db, _ := database.GetDB()
	res, err := db.Exec(`INSERT INTO vpn_virtual_ips (client_id, ip, label, restricted) VALUES (?, ?, ?, ?)`,
		clientID, vip, label, restricted)
	if err != nil {
		router.JSONError(w, "failed to add virtual IP: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vipID, _ := res.LastInsertId()

	s.syncConfig()         // write the extra AllowedIPs into wg0.conf
	requestFirewallApply() // rebuild the vpn_acl table (drop/accept for restricted vips)

	router.JSON(w, VirtualIP{ID: vipID, IP: vip, Label: label, Restricted: restricted == 1, AllowedClientIDs: []int64{}})
}

// handleListVirtualIPs  GET /api/wg/peers/{id}/vips
func (s *Service) handleListVirtualIPs(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}
	clientID, err := clientIDForPeerIP(peer.IPAddress)
	if err != nil {
		router.JSON(w, []VirtualIP{})
		return
	}
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	rows, err := db.Query(`SELECT id, ip, label, restricted FROM vpn_virtual_ips WHERE client_id = ? ORDER BY ip`, clientID)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	list := []VirtualIP{}
	for rows.Next() {
		var v VirtualIP
		var restricted int
		if err := rows.Scan(&v.ID, &v.IP, &v.Label, &restricted); err != nil {
			continue
		}
		v.Restricted = restricted == 1
		v.AllowedClientIDs = loadVIPAllowed(v.ID)
		list = append(list, v)
	}
	router.JSON(w, list)
}

// handleSetVirtualIPACL  PUT /api/wg/vips/{vipId}/acl
// Sets whether a virtual IP is restricted and replaces its allow-list of source peers.
func (s *Service) handleSetVirtualIPACL(w http.ResponseWriter, r *http.Request) {
	vipID := router.ExtractPathParam(r, "/api/wg/vips/")
	if vipID == "" {
		router.JSONError(w, "virtual IP id required", http.StatusBadRequest)
		return
	}
	var req struct {
		Restricted       *bool   `json:"restricted"`
		AllowedClientIDs []int64 `json:"allowedClientIds"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	var exists int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vpn_virtual_ips WHERE id = ?`, vipID).Scan(&exists); err != nil || exists == 0 {
		router.JSONError(w, "virtual IP not found", http.StatusNotFound)
		return
	}
	if req.Restricted != nil {
		restricted := 0
		if *req.Restricted {
			restricted = 1
		}
		if _, err := db.Exec(`UPDATE vpn_virtual_ips SET restricted = ? WHERE id = ?`, restricted, vipID); err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Replace the allow-list. The INSERT...SELECT guarantees each source_client_id
	// references a real client (integrity + validation); OR IGNORE handles duplicates.
	if _, err := db.Exec(`DELETE FROM vpn_virtual_ip_acl WHERE virtual_ip_id = ?`, vipID); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, cid := range req.AllowedClientIDs {
		db.Exec(`INSERT OR IGNORE INTO vpn_virtual_ip_acl (virtual_ip_id, source_client_id)
		         SELECT ?, id FROM vpn_clients WHERE id = ?`, vipID, cid)
	}
	requestFirewallApply() // rebuild the vpn_acl table with the new allow-list
	router.JSON(w, map[string]string{"status": "ok"})
}

// handleDeleteVirtualIP  DELETE /api/wg/vips/{vipId}
func (s *Service) handleDeleteVirtualIP(w http.ResponseWriter, r *http.Request) {
	vipID := router.ExtractPathParam(r, "/api/wg/vips/")
	if vipID == "" {
		router.JSONError(w, "virtual IP id required", http.StatusBadRequest)
		return
	}
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	res, err := db.Exec(`DELETE FROM vpn_virtual_ips WHERE id = ?`, vipID)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		router.JSONError(w, "virtual IP not found", http.StatusNotFound)
		return
	}
	s.syncConfig()
	requestFirewallApply()
	router.JSON(w, map[string]string{"status": "deleted"})
}
