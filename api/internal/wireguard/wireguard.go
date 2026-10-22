package wireguard

import (
	"fmt"
	"log"
	"os"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// stripSensitiveKeys removes private and preshared keys from a peer for safe API response
func stripSensitiveKeys(peer *Peer) {
	peer.PrivateKey = ""
	peer.PresharedKey = ""
}

// encryptPeerKeys encrypts private and preshared keys for storage
func encryptPeerKeys(peer *Peer) (privateKeyEnc, presharedKeyEnc string, err error) {
	if peer.PrivateKey != "" {
		privateKeyEnc, err = helper.Encrypt(peer.PrivateKey)
		if err != nil {
			return "", "", fmt.Errorf("encrypt private key: %w", err)
		}
	}
	if peer.PresharedKey != "" {
		presharedKeyEnc, err = helper.Encrypt(peer.PresharedKey)
		if err != nil {
			return "", "", fmt.Errorf("encrypt preshared key: %w", err)
		}
	}
	return privateKeyEnc, presharedKeyEnc, nil
}

// Service handles WireGuard operations
type Service struct {
	config    Config
	peerStore *PeerStore
}

// Package-level service instance for cross-service access
var serviceInstance *Service

// SetService stores the service instance for access by other packages
func SetService(s *Service) {
	serviceInstance = s
}

// GetService returns the stored service instance
func GetService() *Service {
	return serviceInstance
}

// SimplePeer is a minimal peer representation for other services
type SimplePeer struct {
	ID        string
	Name      string
	IPAddress string
}

// ListPeersWithStatus returns all peers with enriched online status
func (s *Service) ListPeersWithStatus() []*Peer {
	peers := s.peerStore.List()
	s.enrichPeersWithStatus(peers)
	return peers
}

// Config holds WireGuard configuration
type Config struct {
	Interface        string
	ListenPort       int
	ServerPubKey     string
	ServerPriKey     string
	Endpoint         string
	IPRange          string
	ServerIP         string // WireGuard server IP (internal, e.g., 10.8.0.1)
	PublicIP         string // Public server IP (e.g., 188.241.210.100)
	DNS              string
	DataDir          string
	HeadscaleIPRange string
}

// Peer represents a WireGuard peer
type Peer struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	PublicKey     string    `json:"publicKey"`
	PrivateKey    string    `json:"privateKey,omitempty"`
	PresharedKey  string    `json:"presharedKey,omitempty"`
	IPAddress     string    `json:"ipAddress"`
	CreatedAt     time.Time `json:"createdAt"`
	LastSeen      time.Time `json:"lastSeen,omitempty"`
	Enabled       bool      `json:"enabled"`
	Online        bool      `json:"online"`
	LastHandshake time.Time `json:"lastHandshake,omitempty"`
	BlockInternet bool      `json:"blockInternet"`
}

// New creates a new WireGuard service
func New(dataDir string) (*Service, error) {
	port := helper.GetEnvInt("WG_PORT")
	serverIP := helper.GetEnv("SERVER_IP")
	wgServerIP := helper.GetEnv("WG_SERVER_IP")
	ipRange := helper.GetEnv("WG_IP_RANGE")
	dns := helper.GetEnv("WG_DNS")
	headscaleIPRange := helper.GetEnv("HEADSCALE_IP_RANGE")

	// Validate IP configurations
	if err := helper.ValidateIP(serverIP); err != nil {
		return nil, fmt.Errorf("invalid SERVER_IP: %v", err)
	}
	if err := helper.ValidateIP(wgServerIP); err != nil {
		return nil, fmt.Errorf("invalid WG_SERVER_IP: %v", err)
	}
	if err := helper.ValidateIP(dns); err != nil {
		return nil, fmt.Errorf("invalid WG_DNS: %v", err)
	}
	if err := helper.ValidateCIDR(ipRange); err != nil {
		return nil, fmt.Errorf("invalid WG_IP_RANGE: %v", err)
	}
	if headscaleIPRange != "" {
		if err := helper.ValidateCIDR(headscaleIPRange); err != nil {
			return nil, fmt.Errorf("invalid HEADSCALE_IP_RANGE: %v", err)
		}
	}

	endpoint := fmt.Sprintf("%s:%d", serverIP, port)

	svc := &Service{
		config: Config{
			Interface:        helper.GetEnv("WG_INTERFACE"),
			ListenPort:       port,
			Endpoint:         endpoint,
			IPRange:          ipRange,
			ServerIP:         wgServerIP,
			PublicIP:         serverIP,
			DNS:              dns,
			DataDir:          dataDir,
			HeadscaleIPRange: headscaleIPRange,
		},
	}

	// Ensure data directory exists
	os.MkdirAll(dataDir, 0700)

	// Initialize server keys
	if err := svc.initServerKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize server keys: %v", err)
	}

	// Initialize peer store
	svc.peerStore = &PeerStore{
		cache:   make(map[string]*Peer),
		dataDir: dataDir,
	}
	// Migrate from legacy peers.json if exists
	if err := svc.peerStore.MigrateLegacyFile(); err != nil {
		log.Printf("Warning: failed to migrate legacy peers.json: %v", err)
	}
	// Load peers from database into cache
	svc.peerStore.Load()

	// Initialize WireGuard interface
	if err := svc.initWireGuard(); err != nil {
		return nil, fmt.Errorf("failed to initialize WireGuard: %v", err)
	}

	log.Printf("WireGuard service initialized, server public key: %s", svc.config.ServerPubKey)
	return svc, nil
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetPeers":          s.handleGetPeers,
		"GetSessions":       s.handleGetSessions,
		"CreatePeer":        s.handleCreatePeer,
		"GetPeer":           s.handleGetPeer,
		"UpdatePeer":        s.handleUpdatePeer,
		"DeletePeer":        s.handleDeletePeer,
		"EnablePeer":        s.handleEnablePeer,
		"DisablePeer":       s.handleDisablePeer,
		"BlockInternet":     s.handleBlockInternet,
		"UnblockInternet":   s.handleUnblockInternet,
		"GetPeerConfig":     s.handleGetPeerConfig,
		"GetPeerQR":         s.handleGetPeerQR,
		"GetServer":         s.handleGetServer,
		"ListVirtualIPs":    s.handleListVirtualIPs,
		"AddVirtualIP":      s.handleAddVirtualIP,
		"DeleteVirtualIP":   s.handleDeleteVirtualIP,
		"SetVirtualIPACL":   s.handleSetVirtualIPACL,
		"VirtualIPCommands": s.handleVirtualIPCommands,
	}
}

func (s *Service) generateClientConfig(peer *Peer, mode string) string {
	allowedIPs := "0.0.0.0/0, ::/0"
	dns := s.config.DNS

	if mode == "split" {
		// Split tunnel: only route VPN and headscale traffic through VPN
		// NOTE: Do NOT add server's public IP - it's the WireGuard endpoint
		// and routing it through the tunnel creates a loop (can't reach endpoint via tunnel).
		// - VPN-only domains: AdGuard rewrites to VPN IP (10.8.0.1) → works through tunnel
		// - Public domains: clients reach via internet/Cloudflare → works
		allowedIPs = s.config.IPRange
		if s.config.HeadscaleIPRange != "" {
			allowedIPs += ", " + s.config.HeadscaleIPRange
		}
		// Keep DNS so AdGuard rewrites work for internal domains
	}

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
`, peer.PrivateKey, peer.IPAddress)

	if dns != "" {
		conf += fmt.Sprintf("DNS = %s\n", dns)
	}

	conf += fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, s.config.ServerPubKey, peer.PresharedKey, s.config.Endpoint, allowedIPs)

	return conf
}
