package wireguard

import (
	"fmt"
	"net/http"
	"time"

	"api/internal/router"
	"api/internal/ws"

	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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

	if req.Name == "" {
		router.JSONError(w, "name is required", http.StatusBadRequest)
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
		IPAddress:    s.peerStore.AllocateIP(s.config.IPRange),
		CreatedAt:    time.Now(),
		Enabled:      true,
	}

	s.peerStore.Add(peer)
	s.syncConfig()

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
	s.peerStore.Delete(id)
	s.syncConfig()

	// Broadcast node stats update
	ws.BroadcastNodeStats()

	w.WriteHeader(http.StatusNoContent)
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
