package dhcp

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

const netPrefix = "/api/dhcp/networks/"
const clientPrefix = "/api/dhcp/clients/"

func (s *Service) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	nets, err := s.listNetworks()
	if err != nil {
		router.JSONError(w, "could not list networks", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"networks": nets})
}

func (s *Service) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	id, ok := router.ExtractPathParamInt(r, netPrefix)
	if !ok {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}
	n, err := s.getNetwork(id)
	if err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	clients, _ := s.clientsWithLive(n)
	router.JSON(w, map[string]any{"network": n, "clients": clients})
}

func (s *Service) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var n Network
	if !router.DecodeJSONOrError(w, r, &n) {
		return
	}
	others, err := s.otherNetworks(0)
	if err != nil {
		router.JSONError(w, "could not read networks", http.StatusInternalServerError)
		return
	}
	if err := validateNetwork(&n, others); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := s.createNetwork(&n)
	if err != nil {
		router.JSONError(w, "could not save network: "+err.Error(), http.StatusInternalServerError)
		return
	}
	n.ID = id
	if err := s.Reconcile(&n); err != nil {
		// Roll back the DB row so a network that couldn't be brought up doesn't linger.
		_ = s.deleteNetwork(id)
		router.JSONError(w, "network saved but could not be applied (rolled back): "+err.Error(), http.StatusBadRequest)
		return
	}
	router.JSON(w, map[string]any{"network": n})
}

func (s *Service) handleUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	id, ok := router.ExtractPathParamInt(r, netPrefix)
	if !ok {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}
	existing, err := s.getNetwork(id)
	if err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	var n Network
	if !router.DecodeJSONOrError(w, r, &n) {
		return
	}
	n.ID = id
	n.Iface = existing.Iface // the interface is immutable once created
	others, err := s.otherNetworks(id)
	if err != nil {
		router.JSONError(w, "could not read networks", http.StatusInternalServerError)
		return
	}
	if err := validateNetwork(&n, others); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.updateNetwork(&n); err != nil {
		router.JSONError(w, "could not save network", http.StatusInternalServerError)
		return
	}
	if err := s.Reconcile(&n); err != nil {
		router.JSONError(w, "saved but could not apply: "+err.Error(), http.StatusBadRequest)
		return
	}
	router.JSON(w, map[string]any{"network": n})
}

func (s *Service) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	id, ok := router.ExtractPathParamInt(r, netPrefix)
	if !ok {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}
	n, err := s.getNetwork(id)
	if err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	_ = s.writeDnsmasqDisabled(n) // stop DHCP first
	if err := s.RemoveNetwork(n); err != nil {
		router.JSONError(w, "could not remove interface config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.deleteNetwork(id); err != nil {
		router.JSONError(w, "could not delete network", http.StatusInternalServerError)
		return
	}
	removeLeaseFile(n.Iface) // purge stale dnsmasq leases so a future net on this NIC starts clean
	s.reapplyReachability()
	router.JSON(w, map[string]any{"ok": true})
}

func (s *Service) handleListClients(w http.ResponseWriter, r *http.Request) {
	id, ok := router.ExtractPathParamInt(r, netPrefix)
	if !ok {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}
	n, err := s.getNetwork(id)
	if err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	clients, err := s.clientsWithLive(n)
	if err != nil {
		router.JSONError(w, "could not list clients", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"clients": clients})
}

func (s *Service) handleApproveClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	if c.Blocked {
		router.JSONError(w, "device is blocked — unblock it first", http.StatusConflict)
		return
	}
	if err := s.setClientApproved(c.ID, true); err != nil {
		router.JSONError(w, "could not approve", http.StatusInternalServerError)
		return
	}
	audit(r, "lan_device_approve", "Approved LAN device "+c.label())
	s.devicesChanged(c.NetworkID) // pin its IP and open its firewall gate
	router.JSON(w, map[string]any{"ok": true})
}

func (s *Service) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	var req struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	n, err := s.getNetwork(c.NetworkID)
	if err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if req.IP != "" {
		ip := net.ParseIP(req.IP)
		_, ipnet, _ := net.ParseCIDR(n.CIDR)
		if ip == nil || ip.To4() == nil || ipnet == nil || !ipnet.Contains(ip) || ip.String() == n.GatewayIP {
			router.JSONError(w, "reservation IP must be inside the subnet and not the gateway", http.StatusBadRequest)
			return
		}
	}
	if err := s.setClientReservation(c.ID, req.IP, strings.TrimSpace(req.Name)); err != nil {
		router.JSONError(w, "could not save reservation", http.StatusInternalServerError)
		return
	}
	s.devicesChanged(c.NetworkID) // a changed reservation IP moves the per-device gate
	router.JSON(w, map[string]any{"ok": true})
}

// handleGetClient returns one LAN device with its live state and the VPN clients allowed to
// reach it. GET /api/dhcp/clients/{id}
func (s *Service) handleGetClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	if n, err := s.getNetwork(c.NetworkID); err == nil {
		if live, err := s.clientsWithLive(n); err == nil {
			for i := range live {
				if live[i].ID == c.ID {
					c = &live[i]
				}
			}
		}
	}
	allowed, err := s.listDeviceACL(c.ID)
	if err != nil {
		router.JSONError(w, "could not read access", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"client": c, "allowed": allowed})
}

// handleBlockClient denies a device an address and drops its traffic by MAC (it also loses its
// approval). POST /api/dhcp/clients/{id}/block
func (s *Service) handleBlockClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	if err := s.setClientBlocked(c.ID, true, false); err != nil {
		router.JSONError(w, "could not block", http.StatusInternalServerError)
		return
	}
	audit(r, "lan_device_block", "Blocked LAN device "+c.label())
	s.devicesChanged(c.NetworkID)
	router.JSON(w, map[string]any{"ok": true})
}

// handleUnblockClient lifts a block. In "approve" mode the device then waits for approval again;
// in "auto" mode it is approved as any new device would be. POST /api/dhcp/clients/{id}/unblock
func (s *Service) handleUnblockClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	n, err := s.getNetwork(c.NetworkID)
	if err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	if err := s.setClientBlocked(c.ID, false, n.Mode == "auto"); err != nil {
		router.JSONError(w, "could not unblock", http.StatusInternalServerError)
		return
	}
	audit(r, "lan_device_unblock", "Unblocked LAN device "+c.label())
	s.devicesChanged(c.NetworkID)
	router.JSON(w, map[string]any{"ok": true})
}

// handleSetInternet turns a device's internet access on or off.
// PUT /api/dhcp/clients/{id}/internet {"enabled":bool}
func (s *Service) handleSetInternet(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if err := s.setClientInternet(c.ID, req.Enabled); err != nil {
		router.JSONError(w, "could not save", http.StatusInternalServerError)
		return
	}
	state := "off"
	if req.Enabled {
		state = "on"
	}
	audit(r, "lan_device_internet", "Internet "+state+" for LAN device "+c.label())
	s.devicesChanged(c.NetworkID)
	router.JSON(w, map[string]any{"ok": true})
}

// handleAddDeviceACL lets a VPN client reach a device (bidirectional: and the device it), or changes
// an existing grant's direction. The device gets its VPN address on its first grant.
// POST /api/dhcp/clients/{id}/acl {"client_id":n,"bidirectional":bool}
func (s *Service) handleAddDeviceACL(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	var req struct {
		ClientID      int64 `json:"client_id"`
		Bidirectional bool  `json:"bidirectional"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	vpnIP, err := s.clientIPByID(req.ClientID)
	if err != nil {
		router.JSONError(w, "unknown VPN client", http.StatusBadRequest)
		return
	}
	if err := s.assignVPNIP(c.ID); err != nil {
		if errors.Is(err, errNoVPNAddress) {
			router.JSONError(w, err.Error(), http.StatusConflict)
		} else {
			router.JSONError(w, "could not give the device a VPN address", http.StatusInternalServerError)
		}
		return
	}
	if err := s.setDeviceACL(c.ID, req.ClientID, req.Bidirectional); err != nil {
		router.JSONError(w, "could not grant access", http.StatusInternalServerError)
		return
	}
	way := "one-way"
	if req.Bidirectional {
		way = "two-way"
	}
	audit(r, "lan_device_access", "Granted VPN client "+vpnIP+" "+way+" access to LAN device "+c.label())
	s.devicesChanged(c.NetworkID)
	router.JSON(w, map[string]any{"ok": true})
}

// handleRemoveDeviceACL revokes a VPN client's access to a device.
// DELETE /api/dhcp/clients/{id}/acl/{clientId}
func (s *Service) handleRemoveDeviceACL(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	clientID, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		router.JSONError(w, "invalid client id", http.StatusBadRequest)
		return
	}
	if err := s.removeDeviceACL(c.ID, clientID); err != nil {
		router.JSONError(w, "could not revoke access", http.StatusInternalServerError)
		return
	}
	audit(r, "lan_device_access", "Revoked VPN client #"+strconv.FormatInt(clientID, 10)+" access to LAN device "+c.label())
	s.devicesChanged(c.NetworkID)
	router.JSON(w, map[string]any{"ok": true})
}

// handleDeleteClient forgets a device — only while it's offline: a connected device still holds a
// lease and would come straight back as a new device (block it instead).
// DELETE /api/dhcp/clients/{id}
func (s *Service) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	if n, err := s.getNetwork(c.NetworkID); err == nil {
		if live, err := s.clientsWithLive(n); err == nil {
			for _, l := range live {
				if l.ID == c.ID && l.Online {
					router.JSONError(w, "device is connected — it would come back right away; block it instead", http.StatusConflict)
					return
				}
			}
		}
	}
	if err := s.deleteClient(c.ID); err != nil {
		router.JSONError(w, "could not forget device", http.StatusInternalServerError)
		return
	}
	audit(r, "lan_device_forget", "Forgot LAN device "+c.label())
	s.devicesChanged(c.NetworkID) // drop its reservation, block entry and firewall gate
	router.JSON(w, map[string]any{"ok": true})
}

// clientFromPath resolves /api/dhcp/clients/{id} to the client record.
func (s *Service) clientFromPath(w http.ResponseWriter, r *http.Request) (*Client, bool) {
	id, ok := router.ExtractPathParamInt(r, clientPrefix)
	if !ok {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return nil, false
	}
	c, err := s.getClient(id)
	if err != nil {
		router.JSONError(w, "client not found", http.StatusNotFound)
		return nil, false
	}
	return c, true
}

// devicesChanged re-applies everything that depends on a network's devices after one changes:
// the dnsmasq config (reservations, blocked MACs; best-effort, only while the network is enabled
// and its interface is live), the WAN punch-through and the firewall rules.
func (s *Service) devicesChanged(networkID int64) {
	n, err := s.getNetwork(networkID)
	if err != nil {
		s.reapplyReachability()
		return
	}
	if n.Enabled && s.InterfaceReady(n) == nil {
		if err := s.writeDnsmasqConfig(n); err != nil {
			logReconcile(n.Iface, err)
		}
	}
	s.applyDevices(n)
}

// label names a device in audit messages.
func (c *Client) label() string {
	if c.Name != "" {
		return c.Name + " (" + c.MAC + ")"
	}
	return c.MAC
}

// audit records a LAN device change with who made it and from where.
func audit(r *http.Request, event, msg string) {
	actor := ""
	if p := router.CurrentUser(r); p != nil {
		actor = p.Username
	}
	events.Audit("dhcp", event, events.SeverityInfo, actor, helper.GetClientIP(r), msg)
}
