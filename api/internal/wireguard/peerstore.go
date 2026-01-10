package wireguard

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/database"
	"api/internal/domains"
	"api/internal/helper"
)

// PeerStore manages peers with database persistence
type PeerStore struct {
	sync.RWMutex
	cache   map[string]*Peer // in-memory cache for performance
	dataDir string           // for migration from legacy peers.json
}

// MigrateLegacyFile migrates peers from legacy peers.json to database
func (ps *PeerStore) MigrateLegacyFile() error {
	legacyPath := filepath.Join(ps.dataDir, "peers.json")
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No legacy file, nothing to migrate
		}
		return err
	}

	var legacyPeers map[string]*Peer
	if err := json.Unmarshal(data, &legacyPeers); err != nil {
		return fmt.Errorf("failed to parse legacy peers.json: %v", err)
	}

	if len(legacyPeers) == 0 {
		// Empty file, just remove it
		os.Remove(legacyPath)
		return nil
	}

	log.Printf("Migrating %d peers from legacy peers.json to database", len(legacyPeers))

	db, err := database.GetDB()
	if err != nil {
		return err
	}

	for _, peer := range legacyPeers {
		// Encrypt sensitive keys
		privateKeyEnc, presharedKeyEnc, err := encryptPeerKeys(peer)
		if err != nil {
			log.Printf("ERROR: Failed to encrypt keys for peer %s: %v", peer.Name, err)
			continue // Skip this peer, don't lose the key by saving empty
		}

		// Prepare raw_data without sensitive keys
		peerCopy := *peer
		peerCopy.PrivateKey = ""
		peerCopy.PresharedKey = ""
		rawData, _ := json.Marshal(peerCopy)

		enabledInt := 0
		if peer.Enabled {
			enabledInt = 1
		}

		// Insert or update in database
		_, err = db.Exec(`
			INSERT INTO vpn_clients (name, ip, type, external_id, raw_data, acl_policy, public_key, private_key_enc, preshared_key_enc, enabled)
			VALUES (?, ?, 'wireguard', ?, ?, 'selected', ?, ?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET
				name = excluded.name,
				external_id = excluded.external_id,
				raw_data = excluded.raw_data,
				public_key = excluded.public_key,
				private_key_enc = excluded.private_key_enc,
				preshared_key_enc = excluded.preshared_key_enc,
				enabled = excluded.enabled,
				updated_at = CURRENT_TIMESTAMP
		`, peer.Name, peer.IPAddress, peer.ID, string(rawData), peer.PublicKey, privateKeyEnc, presharedKeyEnc, enabledInt)
		if err != nil {
			log.Printf("Warning: failed to migrate peer %s: %v", peer.Name, err)
		}
	}

	// Rename legacy file to backup
	backupPath := legacyPath + ".migrated"
	if err := os.Rename(legacyPath, backupPath); err != nil {
		log.Printf("Warning: could not rename legacy peers.json: %v", err)
	} else {
		log.Printf("Legacy peers.json migrated and renamed to peers.json.migrated")
	}

	return nil
}

// Load loads peers from database into cache
func (ps *PeerStore) Load() error {
	ps.Lock()
	defer ps.Unlock()

	db, err := database.GetDB()
	if err != nil {
		return err
	}

	rows, err := db.Query(`
		SELECT external_id, name, ip, public_key, private_key_enc, preshared_key_enc, enabled, created_at
		FROM vpn_clients
		WHERE type = 'wireguard' AND external_id IS NOT NULL
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	ps.cache = make(map[string]*Peer)
	for rows.Next() {
		var id, name, ip string
		var publicKey, privateKeyEnc, presharedKeyEnc sql.NullString
		var enabled int
		var createdAt time.Time

		if err := rows.Scan(&id, &name, &ip, &publicKey, &privateKeyEnc, &presharedKeyEnc, &enabled, &createdAt); err != nil {
			log.Printf("Warning: failed to scan peer row: %v", err)
			continue
		}

		peer := &Peer{
			ID:        id,
			Name:      name,
			IPAddress: ip,
			PublicKey: publicKey.String,
			Enabled:   enabled == 1,
			CreatedAt: createdAt,
		}

		// Decrypt sensitive keys
		if privateKeyEnc.Valid && privateKeyEnc.String != "" {
			if decrypted, err := helper.Decrypt(privateKeyEnc.String); err == nil {
				peer.PrivateKey = decrypted
			}
		}
		if presharedKeyEnc.Valid && presharedKeyEnc.String != "" {
			if decrypted, err := helper.Decrypt(presharedKeyEnc.String); err == nil {
				peer.PresharedKey = decrypted
			}
		}

		ps.cache[id] = peer
	}

	log.Printf("Loaded %d WireGuard peers from database", len(ps.cache))
	return nil
}

// Add adds or updates a peer in database and cache
func (ps *PeerStore) Add(peer *Peer) {
	ps.Lock()
	defer ps.Unlock()

	db, err := database.GetDB()
	if err != nil {
		return
	}

	// Encrypt sensitive keys
	privateKeyEnc, presharedKeyEnc, err := encryptPeerKeys(peer)
	if err != nil {
		log.Printf("ERROR: Failed to encrypt keys for peer %s: %v", peer.Name, err)
		return
	}

	// Prepare raw_data without sensitive keys
	peerCopy := *peer
	peerCopy.PrivateKey = ""
	peerCopy.PresharedKey = ""
	rawData, _ := json.Marshal(peerCopy)

	enabledInt := 0
	if peer.Enabled {
		enabledInt = 1
	}

	// Upsert to database
	_, err = db.Exec(`
		INSERT INTO vpn_clients (name, ip, type, external_id, raw_data, acl_policy, public_key, private_key_enc, preshared_key_enc, enabled)
		VALUES (?, ?, 'wireguard', ?, ?, 'selected', ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			name = excluded.name,
			external_id = excluded.external_id,
			raw_data = excluded.raw_data,
			public_key = excluded.public_key,
			private_key_enc = excluded.private_key_enc,
			preshared_key_enc = excluded.preshared_key_enc,
			enabled = excluded.enabled,
			updated_at = CURRENT_TIMESTAMP
	`, peer.Name, peer.IPAddress, peer.ID, string(rawData), peer.PublicKey, privateKeyEnc, presharedKeyEnc, enabledInt)
	if err != nil {
		log.Printf("Warning: failed to save peer %s: %v", peer.Name, err)
		return
	}

	// Update cache with a copy
	peerForCache := *peer
	ps.cache[peer.ID] = &peerForCache
}

// Get returns a copy of a peer by ID
func (ps *PeerStore) Get(id string) *Peer {
	ps.RLock()
	defer ps.RUnlock()
	if p, ok := ps.cache[id]; ok {
		// Return a copy to prevent modification of cached data
		peerCopy := *p
		return &peerCopy
	}
	return nil
}

// Delete removes a peer from database and cache
func (ps *PeerStore) Delete(id string) {
	ps.Lock()
	peer := ps.cache[id]
	delete(ps.cache, id)
	ps.Unlock()

	if peer == nil {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		return
	}

	// Get vpn_client id and delete associated domain routes
	var clientID int
	err = db.QueryRow(`SELECT id FROM vpn_clients WHERE ip = ? AND type = 'wireguard'`, peer.IPAddress).Scan(&clientID)
	if err == nil && clientID > 0 {
		domains.DeleteClientRoutes(clientID)
	}

	_, err = db.Exec(`DELETE FROM vpn_clients WHERE ip = ? AND type = 'wireguard'`, peer.IPAddress)
	if err != nil {
		log.Printf("Warning: failed to delete peer %s from database: %v", id, err)
	}
}

// List returns copies of all peers
func (ps *PeerStore) List() []*Peer {
	ps.RLock()
	defer ps.RUnlock()
	list := make([]*Peer, 0, len(ps.cache))
	for _, p := range ps.cache {
		// Return copies to prevent modification of cached data
		peerCopy := *p
		list = append(list, &peerCopy)
	}
	// Sort by creation time
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})
	return list
}

// AllocateIP allocates a new IP address for a peer
func (ps *PeerStore) AllocateIP(ipRange string) string {
	ps.RLock()
	defer ps.RUnlock()

	usedIPs := make(map[string]bool)
	for _, p := range ps.cache {
		usedIPs[p.IPAddress] = true
	}

	baseIP, maskBits := parseIPRange(ipRange)
	if baseIP == nil {
		baseIP = []byte{100, 65, 0, 0}
		maskBits = 16
	}

	numIPs := 1 << (32 - maskBits)

	for i := 2; i < numIPs; i++ {
		ip := make([]byte, 4)
		copy(ip, baseIP)
		ip[3] = byte((int(baseIP[3]) + i) & 0xFF)
		ip[2] = byte((int(baseIP[2]) + (int(baseIP[3])+i)/256) & 0xFF)
		ip[1] = byte((int(baseIP[1]) + (int(baseIP[2])+(int(baseIP[3])+i)/256)/256) & 0xFF)

		ipStr := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
		if !usedIPs[ipStr] {
			return ipStr
		}
	}
	return ""
}

func parseIPRange(cidr string) ([]byte, int) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return nil, 0
	}
	ipParts := strings.Split(parts[0], ".")
	if len(ipParts) != 4 {
		return nil, 0
	}
	ip := make([]byte, 4)
	for i, p := range ipParts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return nil, 0
		}
		ip[i] = byte(v)
	}
	mask, err := strconv.Atoi(parts[1])
	if err != nil || mask < 0 || mask > 32 {
		return nil, 0
	}
	return ip, mask
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use time-based ID if crypto/rand fails (extremely rare)
		log.Printf("Warning: crypto/rand failed, using time-based ID: %v", err)
		binary.BigEndian.PutUint64(b, uint64(time.Now().UnixNano()))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
