package dhcp

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"api/internal/domains"
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
	egressMu.Lock() // held until the choice is saved, so no other save takes the address meanwhile
	defer egressMu.Unlock()
	if n.Egress, err = s.checkEgress(n.Egress, 0); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if n.Services, err = normalizeServices(n.Services); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if (n.NATEnabled || n.Egress != "" || widens(effectiveServices(nil, nil), effectiveServices(&n, nil))) && !router.StepUp(w, r) {
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
		_, _ = s.deleteNetwork(id) // brand new: no devices, so no routes
		router.JSONError(w, "network saved but could not be applied (rolled back): "+err.Error(), http.StatusBadRequest)
		return
	}
	auditNetwork(r, &n, nil)
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
	// The address is checked only when it changes: one that left the server must not stop the
	// network's other settings from being saved (its devices are already without internet).
	egressMu.Lock() // held until the choice is saved, so no other save takes the address meanwhile
	defer egressMu.Unlock()
	// Compare with the network as it is now: a save that finished meanwhile counts.
	if existing, err = s.getNetwork(id); err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	if n.Egress != existing.Egress {
		if n.Egress, err = s.checkEgress(n.Egress, 0); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if n.Services, err = normalizeServices(n.Services); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	grows := (n.NATEnabled && !existing.NATEnabled) || n.Egress != existing.Egress ||
		widens(effectiveServices(existing, nil), effectiveServices(&n, nil))
	if grows && !router.StepUp(w, r) {
		return
	}
	if err := s.updateNetwork(&n); err != nil {
		router.JSONError(w, "could not save network", http.StatusInternalServerError)
		return
	}
	auditNetwork(r, &n, existing)
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
	removed, err := s.deleteNetwork(id)
	if err != nil {
		router.JSONError(w, "could not delete network", http.StatusInternalServerError)
		return
	}
	audit(r, "lan_network", "Deleted network "+n.Iface+" ("+n.CIDR+")"+routesNote(removed))
	removeLeaseFile(n.Iface) // purge stale dnsmasq leases so a future net on this NIC starts clean
	s.reapplyReachability()
	removed.Apply()
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

// handleGetClient returns one LAN device with its live state, the VPN clients allowed to reach it
// and the domain routes to it. GET /api/dhcp/clients/{id}
func (s *Service) handleGetClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	netEgress, netServices := "", ""
	if n, err := s.getNetwork(c.NetworkID); err == nil {
		netEgress, netServices = n.Egress, n.Services
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
	routes, err := domains.LANDeviceRoutes(s.db, c.ID)
	if err != nil {
		router.JSONError(w, "could not read domain routes", http.StatusInternalServerError)
		return
	}
	inbound, err := s.listInbound(c.ID)
	if err != nil {
		router.JSONError(w, "could not read incoming rules", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"client": c, "allowed": allowed, "routes": routes, "inbound": inbound,
		"egress": s.egressOffer(), "network_egress": netEgress, "services": servicesInfo(), "network_services": netServices})
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

// handleSetInternet turns a device's internet access on or off, and sets the internet address it
// leaves from (egress_ip) and what it may reach out there (services, "" = its network's); either
// left out stays as it is. A step-up is due whenever its access grows while on: switching on,
// another address, or a service it didn't have. Off, or taking a service away, needs none.
// PUT /api/dhcp/clients/{id}/internet
// {"enabled":bool,"egress_ip"?:string,"services"?:string,"inbound"?:[{"entry","sources":[...]}]}
// Incoming (inbound.go) needs the device's own dedicated address; moving it to another address
// deletes its incoming list in the same save.
func (s *Service) handleSetInternet(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	n, err := s.getNetwork(c.NetworkID)
	if err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	var req struct {
		Enabled  bool            `json:"enabled"`
		Egress   *string         `json:"egress_ip"`
		Services *string         `json:"services"`
		Inbound  *[]inboundEntry `json:"inbound"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	egressMu.Lock() // held until the choice is saved, so no other save takes the address meanwhile
	defer egressMu.Unlock()
	// Work on the device and its network as they are now: a save that finished meanwhile (an
	// address move, say) must not be undone by writing back what was read before it.
	if c, err = s.getClient(c.ID); err != nil {
		router.JSONError(w, "device not found", http.StatusNotFound)
		return
	}
	if n, err = s.getNetwork(c.NetworkID); err != nil {
		router.JSONError(w, "network not found", http.StatusNotFound)
		return
	}
	egress, services := c.Egress, c.Services
	if req.Egress != nil && *req.Egress != c.Egress {
		if egress, err = s.checkEgress(*req.Egress, c.ID); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if req.Enabled && !c.Internet {
		// Back on with the address it already has: it must still be one the device may hold.
		if err := s.checkOwnEgress(c); err != nil {
			router.JSONError(w, err.Error()+"; pick another address", http.StatusConflict)
			return
		}
	}
	if req.Services != nil && *req.Services != c.Services {
		if services, err = normalizeServices(*req.Services); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	curIn, err := s.listInbound(c.ID)
	if err != nil {
		router.JSONError(w, "could not read incoming rules", http.StatusInternalServerError)
		return
	}
	inbound := curIn
	moved := egress != c.Egress
	switch {
	case req.Inbound != nil && moved && len(*req.Inbound) > 0:
		router.JSONError(w, "incoming rules belong to an address: change the address first, then add them", http.StatusBadRequest)
		return
	case req.Inbound != nil:
		if inbound, err = normalizeInbound(*req.Inbound); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	case moved:
		inbound = nil // they go with the address they were on
	}
	// Only on the device's own dedicated address, still one it may hold: checked when this save
	// turns internet on or opens more. Switching off or narrowing always goes through, whatever
	// state the address is in (a device on a missing or contested address is closed anyway).
	if len(inbound) > 0 && ((req.Enabled && !c.Internet) || widensInbound(curIn, inbound)) {
		if dedicatedIP(egress) == "" {
			router.JSONError(w, "incoming needs this device's own dedicated address", http.StatusConflict)
			return
		}
		if err := s.checkOwnEgress(&Client{ID: c.ID, Egress: egress}); err != nil {
			router.JSONError(w, err.Error(), http.StatusConflict)
			return
		}
	}
	inChanged := inboundLabel(inbound) != inboundLabel(curIn)
	if req.Enabled == c.Internet && !moved && services == c.Services && !inChanged {
		router.JSON(w, map[string]any{"ok": true}) // already so: nothing to confirm
		return
	}
	after := effectiveServices(n, &Client{Services: services})
	// Opening or widening incoming needs a step-up even while internet is off: the list goes live
	// when it is switched on, and that must not be its first approval.
	grows := (req.Enabled && (!c.Internet || moved || widens(effectiveServices(n, c), after))) || widensInbound(curIn, inbound)
	if grows && !router.StepUp(w, r) {
		return
	}
	if err := s.saveInternet(c.ID, req.Enabled, egress, services, inbound); err != nil {
		router.JSONError(w, "could not save", http.StatusInternalServerError)
		return
	}
	state := "off"
	if req.Enabled {
		state = "on via " + egressLabel(egress, "the network's default address") + ", to: " + servicesLabel(after)
		if len(inbound) > 0 {
			state += "; incoming: " + inboundLabel(inbound) // what goes live with it
		}
	}
	audit(r, "lan_device_internet", "Internet "+state+" for LAN device "+c.label())
	if inChanged {
		msg := "Incoming to LAN device " + c.label() + ": " + inboundLabel(inbound)
		if moved && req.Inbound == nil {
			msg = "Incoming to LAN device " + c.label() + " removed with its address: was " + inboundLabel(curIn)
		}
		audit(r, "lan_device_inbound", msg)
	}
	s.devicesChanged(c.NetworkID)
	router.JSON(w, map[string]any{"ok": true})
}

// handleSetVPNAccess turns a device's VPN access on or off, with a step-up either way. On gives it a
// VPN address (nobody can reach it until granted); off removes the address, every grant and every
// domain route to it at once.
// PUT /api/dhcp/clients/{id}/vpn {"enabled":bool}
func (s *Service) handleSetVPNAccess(w http.ResponseWriter, r *http.Request) {
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
	if req.Enabled == (c.VPNIP != "") {
		router.JSON(w, map[string]any{"ok": true}) // already so: nothing to confirm
		return
	}
	if req.Enabled && c.Blocked {
		router.JSONError(w, "device is blocked — unblock it first", http.StatusConflict)
		return
	}
	if !router.StepUp(w, r) {
		return
	}
	var removed domains.Removed
	if req.Enabled {
		if err := s.assignVPNIP(c.ID); err != nil {
			if errors.Is(err, errNoVPNAddress) {
				router.JSONError(w, err.Error(), http.StatusConflict)
			} else {
				router.JSONError(w, "could not give the device a VPN address", http.StatusInternalServerError)
			}
			return
		}
		audit(r, "lan_device_vpn", "VPN access on for LAN device "+c.label())
	} else {
		var err error
		if removed, err = s.clearVPNAccess(c.ID); err != nil {
			router.JSONError(w, "could not turn VPN access off", http.StatusInternalServerError)
			return
		}
		audit(r, "lan_device_vpn", "VPN access off for LAN device "+c.label()+" (address and grants removed)"+routesNote(removed))
	}
	s.devicesChanged(c.NetworkID)
	removed.Apply()
	router.JSON(w, map[string]any{"ok": true})
}

// handleAddDeviceACL lets a VPN client reach a device (bidirectional: and the device it), or changes
// an existing grant's direction. Only while the device's VPN access is on.
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
	if ok, err := s.setDeviceACL(c.ID, req.ClientID, req.Bidirectional); err != nil {
		router.JSONError(w, "could not grant access", http.StatusInternalServerError)
		return
	} else if !ok {
		router.JSONError(w, "turn on the device's VPN access first", http.StatusConflict)
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

// handleDeleteClient forgets a device — only while it's offline (presence.go): a connected device
// would come straight back as a new device (block it instead). One that is gone but still holds a
// lease stays forgotten until that lease is renewed or runs out.
// DELETE /api/dhcp/clients/{id}
func (s *Service) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.clientFromPath(w, r)
	if !ok {
		return
	}
	n, err := s.getNetwork(c.NetworkID)
	if err == nil {
		if live, err := s.clientsWithLive(n); err == nil {
			for _, l := range live {
				if l.ID == c.ID && l.Online {
					router.JSONError(w, "device is connected — it would come back right away; block it instead", http.StatusConflict)
					return
				}
			}
		}
		// Offline but still holding a lease: keep the lease file from bringing it straight back.
		s.rememberForgotten(n, c.MAC)
	}
	removed, err := s.deleteClient(c.ID)
	if err != nil {
		router.JSONError(w, "could not forget device", http.StatusInternalServerError)
		return
	}
	audit(r, "lan_device_forget", "Forgot LAN device "+c.label()+routesNote(removed))
	s.devicesChanged(c.NetworkID) // drop its reservation, block entry and firewall gate
	removed.Apply()
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

// routesNote names the domain routes a change removed, for its audit message.
func routesNote(removed domains.Removed) string {
	if len(removed) == 0 {
		return ""
	}
	return "; domain routes removed: " + strings.Join(removed.Domains(), ", ")
}

// egressLabel names an internet address in audit messages; def names the "" choice.
func egressLabel(v, def string) string {
	switch v {
	case "":
		return def
	case egressMain:
		return "the server's main address"
	}
	return v
}

// auditNetwork records a network being created (old nil) or changed: its settings, each change
// as "was → now", and its internet defaults (new devices getting internet, the address its
// devices leave from, what they may reach).
func auditNetwork(r *http.Request, n, old *Network) {
	if old == nil {
		audit(r, "lan_network", "Created network "+n.Iface+" ("+n.CIDR+", mode "+n.Mode+", "+onOff(n.Enabled, "enabled", "disabled")+")")
	} else {
		var changed []string
		diff := func(what, was, now string) {
			if was != now {
				changed = append(changed, what+" "+was+" → "+now)
			}
		}
		diff("enabled", onOff(old.Enabled, "yes", "no"), onOff(n.Enabled, "yes", "no"))
		diff("mode", old.Mode, n.Mode)
		diff("subnet", old.CIDR, n.CIDR)
		diff("gateway", old.GatewayIP, n.GatewayIP)
		diff("pool", old.PoolStart+"-"+old.PoolEnd, n.PoolStart+"-"+n.PoolEnd)
		diff("lease", strconv.Itoa(old.LeaseSecs)+"s", strconv.Itoa(n.LeaseSecs)+"s")
		diff("domain", old.Domain, n.Domain)
		if len(changed) > 0 {
			audit(r, "lan_network", "Network "+n.Iface+" changed: "+strings.Join(changed, ", "))
		}
	}
	if (old == nil && n.NATEnabled) || (old != nil && n.NATEnabled != old.NATEnabled) {
		audit(r, "lan_network_internet", "Internet "+onOff(n.NATEnabled, "on", "off")+" for new devices of network "+n.Iface)
	}
	if (old == nil && n.Egress != "") || (old != nil && n.Egress != old.Egress) {
		audit(r, "lan_network_internet", "Network "+n.Iface+" devices go out via "+egressLabel(n.Egress, "the server's main address"))
	}
	if (old == nil && n.Services != "") || (old != nil && n.Services != old.Services) {
		audit(r, "lan_network_internet", "Network "+n.Iface+" devices may reach: "+servicesLabel(effectiveServices(n, nil)))
	}
}

func onOff(b bool, on, off string) string {
	if b {
		return on
	}
	return off
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
