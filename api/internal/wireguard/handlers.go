package wireguard

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"api/internal/events"
	"api/internal/nftables"
	"api/internal/router"
	"api/internal/ws"

	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// requestFirewallApply schedules an nftables reapply if the service is available.
func requestFirewallApply() {
	if nft := nftables.GetService(); nft != nil {
		nft.RequestApply()
	}
}

// validPeerName restricts peer names to a safe charset. The name is reflected into
// the config-download filename (Content-Disposition), so quotes/control characters
// are disallowed; it is stored parameterized and never written into wg0.conf.
var validPeerName = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)

// validatePeerName rejects empty or unsafe peer names (used by create and update).
func validatePeerName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("name is required")
	}
	if !validPeerName.MatchString(name) {
		return fmt.Errorf("name may contain only letters, numbers, spaces, and . _ - (max 64 chars)")
	}
	return nil
}

// HTTP Handlers

func (s *Service) handleGetPeers(w http.ResponseWriter, r *http.Request) {
	peers := s.peerStore.List()
	s.enrichPeersWithStatus(peers)
	// Strip sensitive keys from list response - private keys only returned during creation or config download
	for _, p := range peers {
		stripSensitiveKeys(p)
	}
	router.JSON(w, peers)
}

func (s *Service) handleCreatePeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if err := validatePeerName(req.Name); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	priKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		router.JSONError(w, "failed to generate keys", http.StatusInternalServerError)
		return
	}

	psk, err := wgtypes.GenerateKey()
	if err != nil {
		router.JSONError(w, "failed to generate preshared key", http.StatusInternalServerError)
		return
	}

	peer := &Peer{
		ID:           generateID(),
		Name:         req.Name,
		PrivateKey:   priKey.String(),
		PublicKey:    priKey.PublicKey().String(),
		PresharedKey: psk.String(),
		CreatedAt:    time.Now(),
		Enabled:      true,
	}

	// Allocate the IP and insert atomically so concurrent creates can't collide on
	// the same address (which the ON CONFLICT(ip) upsert would resolve by overwriting).
	if err := s.peerStore.AllocateAndAdd(peer, s.config.IPRange); err != nil {
		router.JSONError(w, err.Error(), http.StatusConflict)
		return
	}
	s.syncConfig()

	events.Log("wireguard", "peer_added", events.SeverityInfo,
		fmt.Sprintf("Peer %q added (%s)", peer.Name, peer.IPAddress))

	// Broadcast node stats update
	ws.BroadcastNodeStats()

	w.WriteHeader(http.StatusCreated)
	router.JSON(w, peer)
}

func (s *Service) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}
	s.enrichPeersWithStatus([]*Peer{peer})
	router.JSON(w, peer)
}

func (s *Service) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	var req struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Name != nil {
		if err := validatePeerName(*req.Name); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		peer.Name = *req.Name
	}
	if req.Enabled != nil {
		peer.Enabled = *req.Enabled
	}

	s.peerStore.Add(peer)
	s.syncConfig()
	router.JSON(w, peer)
}

func (s *Service) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id) // capture name/IP before removal for the activity feed
	s.peerStore.Delete(id)
	s.syncConfig()

	if peer != nil {
		events.Log("wireguard", "peer_removed", events.SeverityInfo,
			fmt.Sprintf("Peer %q removed (%s)", peer.Name, peer.IPAddress))
	}

	// Drop the peer's IP from any nftables sets (e.g. no_internet_peers).
	requestFirewallApply()

	// Broadcast node stats update
	ws.BroadcastNodeStats()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleBlockInternet(w http.ResponseWriter, r *http.Request) {
	s.setBlockInternet(w, r, true)
}

func (s *Service) handleUnblockInternet(w http.ResponseWriter, r *http.Request) {
	s.setBlockInternet(w, r, false)
}

func (s *Service) setBlockInternet(w http.ResponseWriter, r *http.Request, block bool) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	if err := s.peerStore.SetBlockInternet(id, block); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	requestFirewallApply()

	peer = s.peerStore.Get(id)
	stripSensitiveKeys(peer)
	router.JSON(w, peer)
}

func (s *Service) handleEnablePeer(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	peer.Enabled = true
	s.peerStore.Add(peer)
	s.syncConfig()
	// Return peer without sensitive keys
	stripSensitiveKeys(peer)
	router.JSON(w, peer)
}

func (s *Service) handleDisablePeer(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	peer.Enabled = false
	s.peerStore.Add(peer)
	s.syncConfig()
	// Return peer without sensitive keys
	stripSensitiveKeys(peer)
	router.JSON(w, peer)
}

func (s *Service) handleGetPeerConfig(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "full"
	}

	conf := s.generateClientConfig(peer, mode)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", peer.Name))
	w.Write([]byte(conf))
}

func (s *Service) handleGetPeerQR(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "full"
	}

	conf := s.generateClientConfig(peer, mode)
	png, err := qrcode.Encode(conf, qrcode.Medium, 256)
	if err != nil {
		router.JSONError(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

func (s *Service) handleGetServer(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]interface{}{
		"publicKey":        s.config.ServerPubKey,
		"endpoint":         s.config.Endpoint,
		"port":             s.config.ListenPort,
		"ipRange":          s.config.IPRange,
		"serverIP":         s.config.ServerIP,
		"interface":        s.config.Interface,
		"dns":              s.config.DNS,
		"headscaleIPRange": s.config.HeadscaleIPRange,
	})
}
