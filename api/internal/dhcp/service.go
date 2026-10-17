package dhcp

import (
	"log"
	"net"
	"net/http"
	"strings"

	"api/internal/database"
	"api/internal/nftables"
	"api/internal/router"
)

// Service owns the DHCP-managed private networks: interface addressing (netplan), the dnsmasq
// DHCP-only config, lease/reservation registration, and VPN reachability via the nft forward
// chain. It reuses the firewall's nftables service for the reachability table.
type Service struct {
	db  *database.DB
	nft *nftables.Service
}

// New creates the DHCP service. nft may be nil (reachability rules are then skipped, logged).
func New(db *database.DB, nft *nftables.Service) *Service {
	s := &Service{db: db, nft: nft}
	if nft != nil {
		nft.RegisterTable(NewReachabilityTable(db))
	}
	return s
}

// Handlers maps the router's handler names (see configs/endpoints.json, service "dhcp") to
// methods. Session-gated like the rest of the admin API.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"ListInterfaces": s.handleListInterfaces,
		"ListNetworks":   s.handleListNetworks,
		"CreateNetwork":  s.handleCreateNetwork,
		"GetNetwork":     s.handleGetNetwork,
		"UpdateNetwork":  s.handleUpdateNetwork,
		"DeleteNetwork":  s.handleDeleteNetwork,
		"ListClients":    s.handleListClients,
		"AddACL":         s.handleAddACL,
		"RemoveACL":      s.handleRemoveACL,
		"ApproveClient":  s.handleApproveClient,
		"UpdateClient":   s.handleUpdateClient,
		"DeleteClient":   s.handleDeleteClient,
	}
}

// Reconcile re-applies the live state for a network: the interface address (netplan, with
// rollback), then the dnsmasq config (validated), then the reachability rules. On enable it
// fails closed — a network whose interface isn't live does not get a running DHCP server.
func (s *Service) Reconcile(n *Network) error {
	if !n.Enabled {
		// Disabled: tear down DHCP for it but leave the interface address in place (the
		// operator may still want the gateway up); reachability rules drop out on reapply.
		if err := s.writeDnsmasqDisabled(n); err != nil {
			return err
		}
		s.reapplyReachability()
		return nil
	}
	if err := s.ApplyNetwork(n); err != nil {
		return err
	}
	if err := s.InterfaceReady(n); err != nil {
		return err // fail closed: no DHCP on an interface that isn't actually up
	}
	ensureIPForward() // routing between wg0 and the segment needs IPv4 forwarding
	if err := s.writeDnsmasqConfig(n); err != nil {
		return err
	}
	s.reapplyReachability()
	return nil
}

// reapplyReachability asks the firewall to rebuild (the reachability table reads the DB each
// build). Best-effort — a nil nft service just means reachability isn't enforced yet.
func (s *Service) reapplyReachability() {
	if s.nft != nil {
		s.nft.RequestApply()
	}
}

// candidateInterface reports whether a NIC may be offered as a managed segment: a real ethernet
// up/down is fine, but never loopback, the VPN NICs, docker/bridge plumbing, or the WAN.
func candidateInterface(name, wan string) bool {
	if name == wan || name == "lo" {
		return false
	}
	for _, p := range []string{"wg", "tailscale", "docker", "br-", "veth", "virbr", "tun", "tap"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func (s *Service) handleListInterfaces(w http.ResponseWriter, r *http.Request) {
	wan, _ := defaultRouteInterface()
	ifaces, err := net.Interfaces()
	if err != nil {
		router.JSONError(w, "could not list interfaces", 500)
		return
	}
	managed := map[string]bool{}
	if nets, err := s.listNetworks(); err == nil {
		for _, n := range nets {
			managed[n.Iface] = true
		}
	}
	type ifaceInfo struct {
		Name    string   `json:"name"`
		Addrs   []string `json:"addrs"`
		Up      bool     `json:"up"`
		Managed bool     `json:"managed"`
	}
	out := []ifaceInfo{}
	for _, in := range ifaces {
		if !candidateInterface(in.Name, wan) {
			continue
		}
		var addrs []string
		if as, err := in.Addrs(); err == nil {
			for _, a := range as {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					addrs = append(addrs, ipn.String())
				}
			}
		}
		out = append(out, ifaceInfo{
			Name: in.Name, Addrs: addrs,
			Up:      in.Flags&net.FlagUp != 0,
			Managed: managed[in.Name],
		})
	}
	router.JSON(w, map[string]any{"interfaces": out, "wan": wan})
}

func logReconcile(iface string, err error) {
	if err != nil {
		log.Printf("dhcp: reconcile %s failed: %v", iface, err)
	}
}
