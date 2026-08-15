package wireguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"

	"api/internal/database"
	"api/internal/events"
	"api/internal/router"
)

// VirtualIP is an extra VPN /32 routed to a peer and (optionally) mapped to a LAN
// device by a DNAT on that peer. When Restricted, only AllowedClientIDs may reach it;
// when Quarantine, it can be reached but can't initiate to other peers — both enforced
// on the server's forward chain by vpn_acl.
type VirtualIP struct {
	ID               int64   `json:"id"`
	IP               string  `json:"ip"`
	Label            string  `json:"label"`
	TargetIP         string  `json:"targetIp,omitempty"`
	TargetPort       int     `json:"targetPort,omitempty"`
	Restricted       bool    `json:"restricted"`
	Quarantine       bool    `json:"quarantine"`
	AllowedClientIDs []int64 `json:"allowedClientIds"`
}

// allocateVirtualIP picks a free IP from the upper half of the WireGuard range, so
// virtual IPs stay visually distinct from peer IPs (assigned from the low end).
// Returns "" if the range is full. Excludes peers, the server IP, and existing vips.
func (s *Service) allocateVirtualIP() string {
	baseIP, maskBits := parseIPRange(s.config.IPRange)
	if baseIP == nil {
		return ""
	}
	// Guard the shift/loop math against a pathological mask: maskBits==0 would make
	// 1<<32 wrap to 0 and numIPs-1 underflow to ~4 billion (a hang). Real WG ranges
	// are /16–/30.
	if maskBits < 8 || maskBits > 30 {
		return ""
	}
	base := binary.BigEndian.Uint32(baseIP)
	numIPs := uint32(1) << uint(32-maskBits)

	used := map[string]bool{s.config.ServerIP: true}
	for _, p := range s.peerStore.List() {
		used[p.IPAddress] = true
	}
	if db, err := database.GetDB(); err == nil {
		if rows, err := db.Query(`SELECT ip FROM vpn_virtual_ips`); err == nil {
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil {
					used[ip] = true
				}
			}
			rows.Close()
		}
	}

	start := numIPs / 2
	if numIPs < 8 {
		start = 2 // tiny range: fall back to scanning from the start
	}
	for i := start; i < numIPs-1; i++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base+i)
		// Skip addresses whose last octet is 0 or 255: even inside a larger
		// prefix they look like network/broadcast addresses and some devices
		// and tools refuse them, so keep vips to unambiguous host addresses.
		if b[3] == 0 || b[3] == 255 {
			continue
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
		if !used[ip] {
			return ip
		}
	}
	return ""
}

// vipChainName sanitizes a virtual-IP label into a valid iptables chain fragment
// (uppercase [A-Z0-9_], length-capped). It is NOT unique on its own — labels can
// repeat or collide after sanitizing; vipChainBase adds the vip id for uniqueness.
func vipChainName(label string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(label) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" {
		name = "VIP"
	}
	if len(name) > 20 {
		name = name[:20]
	}
	return name
}

// vipChainBase builds a per-vip-unique iptables chain base: the sanitized label
// plus the vip's row id. Without the id, two vips whose labels are identical, blank,
// or collide after sanitizing/truncation would share a chain — and tearing one down
// (-F/-X) would flush the other's forward too. The id makes every vip's chain its own.
// Kept ≤ 23 chars so base+"_DNAT" stays within the 28-char iptables chain-name limit.
func vipChainBase(id int64, label string) string {
	name := vipChainName(label)
	suffix := fmt.Sprintf("_%d", id)
	if max := 23 - len(suffix); len(name) > max {
		name = name[:max]
	}
	return name + suffix
}

// generateVIPCommands returns the NAS commands that forward a virtual IP to its
// target device. With a port it forwards only that TCP port (tighter — e.g. just
// the camera's RTSP); with port 0 it forwards all traffic. Chains are named after
// the vip's label, and the comment names the peer (nft-safe: DNAT and MASQUERADE
// live in separate hooked chains).
func generateVIPCommands(id int64, vip, target string, port int, label, peerName string) string {
	base := vipChainBase(id, label)
	dnat, snat := base+"_DNAT", base+"_SNAT"
	peer := peerName
	if peer == "" {
		peer = "the device's host"
	}

	var dnatRule, desc string
	if port > 0 {
		dnatRule = fmt.Sprintf("sudo iptables -t nat -A %s -d %s -p tcp --dport %d -j DNAT --to-destination %s:%d", dnat, vip, port, target, port)
		desc = fmt.Sprintf("TCP %s:%d to %s:%d", vip, port, target, port)
	} else {
		dnatRule = fmt.Sprintf("sudo iptables -t nat -A %s -d %s -j DNAT --to-destination %s", dnat, vip, target)
		desc = fmt.Sprintf("all traffic for %s to %s", vip, target)
	}

	return fmt.Sprintf(`# Run on peer %q — forwards %s.
sudo iptables -t nat -N %s 2>/dev/null; sudo iptables -t nat -N %s 2>/dev/null
sudo iptables -t nat -C PREROUTING  -j %s 2>/dev/null || sudo iptables -t nat -A PREROUTING  -j %s
sudo iptables -t nat -C POSTROUTING -j %s 2>/dev/null || sudo iptables -t nat -A POSTROUTING -j %s
%s
sudo iptables -t nat -A %s -d %s -j MASQUERADE`,
		peer, desc,
		dnat, snat,
		dnat, dnat,
		snat, snat,
		dnatRule,
		snat, target)
}

// generateVIPRemoveCommands undoes generateVIPCommands: unhook the chains from
// PREROUTING/POSTROUTING, then flush and delete them.
func generateVIPRemoveCommands(id int64, label string) string {
	base := vipChainBase(id, label)
	dnat, snat := base+"_DNAT", base+"_SNAT"
	return fmt.Sprintf(`# Undo the forward (run on the same peer).
sudo iptables -t nat -D PREROUTING  -j %s 2>/dev/null
sudo iptables -t nat -D POSTROUTING -j %s 2>/dev/null
sudo iptables -t nat -F %s 2>/dev/null; sudo iptables -t nat -X %s 2>/dev/null
sudo iptables -t nat -F %s 2>/dev/null; sudo iptables -t nat -X %s 2>/dev/null`,
		dnat, snat, dnat, dnat, snat, snat)
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
		Label      string `json:"label"`
		TargetIP   string `json:"targetIp"`
		TargetPort int    `json:"targetPort"`
		Restricted *bool  `json:"restricted"`
		Quarantine *bool  `json:"quarantine"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// The virtual IP is auto-assigned from the upper half of the WG range.
	vip := s.allocateVirtualIP()
	if vip == "" {
		router.JSONError(w, "no free virtual IP in the WireGuard range", http.StatusConflict)
		return
	}

	// The target device (LAN IP + port) is optional — a bare virtual IP is fine.
	target := strings.TrimSpace(req.TargetIP)
	port := 0
	if target != "" {
		if ip := net.ParseIP(target); ip == nil || ip.To4() == nil {
			router.JSONError(w, "device IP must be a valid IPv4 address", http.StatusBadRequest)
			return
		}
		// port 0 = forward every port (e.g. ONVIF, which needs 554 + HTTP + dynamic RTP);
		// a non-zero port must be a valid TCP port — never silently coerce.
		port = req.TargetPort
		if port < 0 || port > 65535 {
			router.JSONError(w, "port must be between 1 and 65535 (leave empty to forward all ports)", http.StatusBadRequest)
			return
		}
	}

	label := strings.TrimSpace(req.Label)
	if len(label) > 64 {
		label = label[:64]
	}
	restricted := 1 // secure default: reachable by no one until peers are opted in
	if req.Restricted != nil && !*req.Restricted {
		restricted = 0
	}
	quarantine := 0
	if req.Quarantine != nil && *req.Quarantine {
		quarantine = 1
	}

	clientID, err := clientIDForPeerIP(peer.IPAddress)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	res, err := db.Exec(`INSERT INTO vpn_virtual_ips (client_id, ip, label, target_ip, target_port, restricted, quarantine) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		clientID, vip, label, target, port, restricted, quarantine)
	if err != nil {
		router.JSONError(w, "failed to add virtual IP: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vipID, _ := res.LastInsertId()

	s.syncConfig()         // write the extra AllowedIPs into wg0.conf
	requestFirewallApply() // rebuild the vpn_acl table (restricted/quarantine rules)

	vipMsg := fmt.Sprintf("Virtual IP %s added to %q", vip, peer.Name)
	if target != "" {
		vipMsg += " → " + target
	}
	events.Log("wireguard", "vip_added", events.SeverityInfo, vipMsg)

	router.JSON(w, VirtualIP{
		ID: vipID, IP: vip, Label: label, TargetIP: target, TargetPort: port,
		Restricted: restricted == 1, Quarantine: quarantine == 1, AllowedClientIDs: []int64{},
	})
}

// handleVirtualIPCommands  GET /api/wg/vips/{id}/commands
// Returns the NAS commands to forward this virtual IP to its stored target device.
func (s *Service) handleVirtualIPCommands(w http.ResponseWriter, r *http.Request) {
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
	var idNum int64
	var vip, target, label, peerName string
	var port int
	if err := db.QueryRow(`SELECT v.id, v.ip, v.target_ip, v.target_port, v.label, COALESCE(c.name, '')
		FROM vpn_virtual_ips v LEFT JOIN vpn_clients c ON v.client_id = c.id
		WHERE v.id = ?`, vipID).Scan(&idNum, &vip, &target, &port, &label, &peerName); err != nil {
		router.JSONError(w, "virtual IP not found", http.StatusNotFound)
		return
	}
	if target == "" {
		router.JSONError(w, "this virtual IP has no target device set", http.StatusBadRequest)
		return
	}
	router.JSON(w, map[string]interface{}{
		"virtualIp":      vip,
		"targetIp":       target,
		"port":           port,
		"commands":       generateVIPCommands(idNum, vip, target, port, label, peerName),
		"removeCommands": generateVIPRemoveCommands(idNum, label),
	})
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
	rows, err := db.Query(`SELECT id, ip, label, target_ip, target_port, restricted, quarantine FROM vpn_virtual_ips WHERE client_id = ? ORDER BY ip`, clientID)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	list := []VirtualIP{}
	for rows.Next() {
		var v VirtualIP
		var restricted, quarantine int
		if err := rows.Scan(&v.ID, &v.IP, &v.Label, &v.TargetIP, &v.TargetPort, &restricted, &quarantine); err != nil {
			continue
		}
		v.Restricted = restricted == 1
		v.Quarantine = quarantine == 1
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
		Quarantine       *bool   `json:"quarantine"`
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
	if req.Quarantine != nil {
		q := 0
		if *req.Quarantine {
			q = 1
		}
		if _, err := db.Exec(`UPDATE vpn_virtual_ips SET quarantine = ? WHERE id = ?`, q, vipID); err != nil {
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
	var vipIP string // captured for the activity feed
	_ = db.QueryRow(`SELECT ip FROM vpn_virtual_ips WHERE id = ?`, vipID).Scan(&vipIP)

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

	events.Log("wireguard", "vip_removed", events.SeverityInfo,
		fmt.Sprintf("Virtual IP %s removed", vipIP))

	router.JSON(w, map[string]string{"status": "deleted"})
}
