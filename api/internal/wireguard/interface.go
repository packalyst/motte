package wireguard

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (s *Service) initServerKeys() error {
	priKeyPath := filepath.Join(s.config.DataDir, "server_private.key")
	pubKeyPath := filepath.Join(s.config.DataDir, "server_public.key")

	if priKeyData, err := os.ReadFile(priKeyPath); err == nil {
		s.config.ServerPriKey = strings.TrimSpace(string(priKeyData))
		if pubKeyData, err := os.ReadFile(pubKeyPath); err == nil {
			s.config.ServerPubKey = strings.TrimSpace(string(pubKeyData))
			return nil
		}
	}

	priKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	s.config.ServerPriKey = priKey.String()
	s.config.ServerPubKey = priKey.PublicKey().String()

	if err := os.WriteFile(priKeyPath, []byte(s.config.ServerPriKey), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(pubKeyPath, []byte(s.config.ServerPubKey), 0644); err != nil {
		return err
	}

	log.Println("Generated new server keys")
	return nil
}

func (s *Service) initWireGuard() error {
	// Check if wireguard module is loaded (don't try modprobe - container doesn't have it)
	if _, err := os.Stat("/sys/module/wireguard"); os.IsNotExist(err) {
		log.Printf("Warning: WireGuard kernel module not loaded on host. Load it with: sudo modprobe wireguard")
	}

	cmd := exec.Command("ip", "link", "show", s.config.Interface)
	if err := cmd.Run(); err != nil {
		log.Printf("Creating WireGuard interface %s", s.config.Interface)
		if err := exec.Command("ip", "link", "add", "dev", s.config.Interface, "type", "wireguard").Run(); err != nil {
			return fmt.Errorf("failed to create interface: %v", err)
		}
	}

	if err := s.syncConfig(); err != nil {
		return err
	}

	if err := exec.Command("ip", "addr", "flush", "dev", s.config.Interface).Run(); err != nil {
		log.Printf("Warning: failed to flush addresses: %v", err)
	}
	// Extract netmask from IPRange env var (e.g., "100.65.0.0/16" -> "/16")
	_, ipNet, err := net.ParseCIDR(s.config.IPRange)
	if err != nil {
		return fmt.Errorf("invalid IP range %s: %v", s.config.IPRange, err)
	}
	ones, _ := ipNet.Mask.Size()
	serverIPWithMask := fmt.Sprintf("%s/%d", s.config.ServerIP, ones)
	if err := exec.Command("ip", "addr", "add", serverIPWithMask, "dev", s.config.Interface).Run(); err != nil {
		return fmt.Errorf("failed to set IP: %v", err)
	}

	if err := exec.Command("ip", "link", "set", "up", "dev", s.config.Interface).Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	s.setupNAT()
	log.Printf("WireGuard interface %s initialized with IP %s", s.config.Interface, s.config.ServerIP)
	return nil
}

func (s *Service) setupNAT() error {
	// Enable IP forwarding by writing directly to sysctl (no shell needed)
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		log.Printf("Warning: failed to enable IP forwarding: %v", err)
	}

	outIface := s.getDefaultInterface()
	if outIface == "" {
		outIface = "eth0"
	}

	// MASQUERADE
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", s.config.IPRange, "-o", outIface, "-j", "MASQUERADE")
	if checkCmd.Run() != nil {
		if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", s.config.IPRange, "-o", outIface, "-j", "MASQUERADE").Run(); err != nil {
			log.Printf("Warning: failed to add NAT MASQUERADE rule: %v", err)
		} else {
			log.Printf("Added NAT MASQUERADE rule for %s via %s", s.config.IPRange, outIface)
		}
	}

	// FORWARD rules
	checkCmd = exec.Command("iptables", "-C", "FORWARD", "-i", s.config.Interface, "-j", "ACCEPT")
	if checkCmd.Run() != nil {
		if err := exec.Command("iptables", "-A", "FORWARD", "-i", s.config.Interface, "-j", "ACCEPT").Run(); err != nil {
			log.Printf("Warning: failed to add FORWARD rule (in): %v", err)
		}
	}

	checkCmd = exec.Command("iptables", "-C", "FORWARD", "-o", s.config.Interface, "-j", "ACCEPT")
	if checkCmd.Run() != nil {
		if err := exec.Command("iptables", "-A", "FORWARD", "-o", s.config.Interface, "-j", "ACCEPT").Run(); err != nil {
			log.Printf("Warning: failed to add FORWARD rule (out): %v", err)
		}
	}

	return nil
}

func (s *Service) getDefaultInterface() string {
	// Parse ip route output directly without shell pipeline
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	// Output format: "default via X.X.X.X dev ethX ..."
	fields := strings.Fields(string(out))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func (s *Service) syncConfig() error {
	confPath := filepath.Join(s.config.DataDir, s.config.Interface+".conf")
	enabledPeers := make(map[string]bool)

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = %d

`, s.config.ServerPriKey, s.config.ListenPort)

	s.peerStore.RLock()
	for _, peer := range s.peerStore.cache {
		if peer.Enabled {
			enabledPeers[peer.PublicKey] = true
			peerConf := fmt.Sprintf("[Peer]\nPublicKey = %s\n", peer.PublicKey)
			if peer.PresharedKey != "" {
				peerConf += fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey)
			}
			peerConf += fmt.Sprintf("AllowedIPs = %s/32\n\n", peer.IPAddress)
			conf += peerConf
		}
	}
	s.peerStore.RUnlock()

	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return err
	}

	// Remove disabled peers
	currentPeers := s.getCurrentPeers()
	for _, pubKey := range currentPeers {
		if !enabledPeers[pubKey] {
			exec.Command("wg", "set", s.config.Interface, "peer", pubKey, "remove").Run()
		}
	}

	return exec.Command("wg", "syncconf", s.config.Interface, confPath).Run()
}

func (s *Service) getCurrentPeers() []string {
	var peers []string
	out, err := exec.Command("wg", "show", s.config.Interface, "peers").Output()
	if err != nil {
		return peers
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			peers = append(peers, line)
		}
	}
	return peers
}

func (s *Service) getWgStatus() map[string]time.Time {
	status := make(map[string]time.Time)
	out, err := exec.Command("wg", "show", s.config.Interface, "dump").Output()
	if err != nil {
		return status
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) >= 5 {
			pubKey := fields[0]
			if ts, err := strconv.ParseInt(fields[4], 10, 64); err == nil && ts > 0 {
				status[pubKey] = time.Unix(ts, 0)
			}
		}
	}
	return status
}

func (s *Service) enrichPeersWithStatus(peers []*Peer) {
	status := s.getWgStatus()
	now := time.Now()

	for _, peer := range peers {
		if handshake, ok := status[peer.PublicKey]; ok {
			peer.LastHandshake = handshake
			peer.Online = now.Sub(handshake) < 3*time.Minute
		} else {
			peer.Online = false
			peer.LastHandshake = time.Time{}
		}
	}
}
