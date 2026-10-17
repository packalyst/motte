package dhcp

import (
	"net"
	"net/http"
	"strconv"
	"strings"

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
	acl, _ := s.listNetworkACL(id)
	router.JSON(w, map[string]any{"network": n, "clients": clients, "acl": acl})
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

func (s *Service) handleAddACL(w http.ResponseWriter, r *http.Request) {
	id, ok := router.ExtractPathParamInt(r, netPrefix)
	if !ok {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		ClientID int64 `json:"client_id"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if _, err := s.clientIPByID(req.ClientID); err != nil {
		router.JSONError(w, "unknown VPN client", http.StatusBadRequest)
		return
	}
	if err := s.addNetworkACL(id, req.ClientID); err != nil {
		router.JSONError(w, "could not grant access", http.StatusInternalServerError)
		return
	}
	s.reapplyReachability()
	router.JSON(w, map[string]any{"ok": true})
}

func (s *Service) handleRemoveACL(w http.ResponseWriter, r *http.Request) {
	id, ok := router.ExtractPathParamInt(r, netPrefix)
	if !ok {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}
	// path: /api/dhcp/networks/{id}/acl/{clientId}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	clientID, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		router.JSONError(w, "invalid client id", http.StatusBadRequest)
		return
	}
	if err := s.removeNetworkACL(id, clientID); err != nil {
		router.JSONError(w, "could not revoke access", http.StatusInternalServerError)
		return
	}
	s.reapplyReachability()
	router.JSON(w, map[string]any{"ok": true})
}

func (s *Service) handleApproveClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	if err := s.setClientApproved(c.ID, true); err != nil {
		router.JSONError(w, "could not approve", http.StatusInternalServerError)
		return
	}
	s.reconcileDnsmasqFor(c.NetworkID)
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
	s.reconcileDnsmasqFor(c.NetworkID)
	router.JSON(w, map[string]any{"ok": true})
}

func (s *Service) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	if err := s.deleteClient(c.ID); err != nil {
		router.JSONError(w, "could not delete client", http.StatusInternalServerError)
		return
	}
	s.reconcileDnsmasqFor(c.NetworkID)
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

// reconcileDnsmasqFor rewrites + reloads a network's dnsmasq config after a reservation change
// (best-effort; only when the network is enabled and its interface is live).
func (s *Service) reconcileDnsmasqFor(networkID int64) {
	n, err := s.getNetwork(networkID)
	if err != nil || !n.Enabled {
		return
	}
	if err := s.InterfaceReady(n); err != nil {
		return
	}
	if err := s.writeDnsmasqConfig(n); err != nil {
		logReconcile(n.Iface, err)
	}
}
