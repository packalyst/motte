package vpn

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/database"
	"api/internal/helper"
)

// PeerTransfer represents WireGuard transfer stats for a peer
type PeerTransfer struct {
	PublicKey string
	Rx        int64 // bytes received
	Tx        int64 // bytes transmitted
}

// GetWgTransfer returns current WireGuard transfer stats per peer
// Parses output of: wg show <interface> transfer
func GetWgTransfer() ([]PeerTransfer, error) {
	iface := helper.GetEnvOptional("WG_INTERFACE", "wg0")

	cmd := exec.Command("wg", "show", iface, "transfer")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var transfers []PeerTransfer
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: <public-key>\t<rx-bytes>\t<tx-bytes>
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		rx, _ := strconv.ParseInt(parts[1], 10, 64)
		tx, _ := strconv.ParseInt(parts[2], 10, 64)

		transfers = append(transfers, PeerTransfer{
			PublicKey: parts[0],
			Rx:        rx,
			Tx:        tx,
		})
	}

	return transfers, nil
}

// GetTrafficTotals returns total tx/rx across all WireGuard peers from database
func GetTrafficTotals() (totalTx, totalRx int64, err error) {
	db, err := database.GetDB()
	if err != nil {
		return 0, 0, err
	}

	err = db.QueryRow(`
		SELECT COALESCE(SUM(total_tx), 0), COALESCE(SUM(total_rx), 0)
		FROM vpn_clients
		WHERE type = 'wireguard'
	`).Scan(&totalTx, &totalRx)

	return totalTx, totalRx, err
}

// GetPeerTrafficStats returns traffic stats for all peers from database
func GetPeerTrafficStats() ([]PeerTrafficInfo, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(`
		SELECT name, ip, total_tx, total_rx
		FROM vpn_clients
		WHERE type = 'wireguard' AND (total_tx > 0 OR total_rx > 0)
		ORDER BY (total_tx + total_rx) DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []PeerTrafficInfo
	for rows.Next() {
		var s PeerTrafficInfo
		if err := rows.Scan(&s.Name, &s.IP, &s.Tx, &s.Rx); err != nil {
			continue
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// PeerTrafficInfo contains traffic info for a single peer
type PeerTrafficInfo struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Tx   int64  `json:"tx"`
	Rx   int64  `json:"rx"`
}

var (
	trafficCtx    context.Context
	trafficCancel context.CancelFunc
	trafficOnce   sync.Once
	trafficMu     sync.Mutex
	lastRateTx    int64
	lastRateRx    int64
)

// StartTrafficSync starts the background traffic sync goroutine
func StartTrafficSync() {
	trafficOnce.Do(func() {
		trafficCtx, trafficCancel = context.WithCancel(context.Background())
		go runTrafficSync(trafficCtx)
		log.Println("VPN traffic sync started")
	})
}

// StopTrafficSync stops the background traffic sync
func StopTrafficSync() {
	if trafficCancel != nil {
		trafficCancel()
	}
}

// GetTrafficRates returns the current tx/rx rates in bytes/sec
func GetTrafficRates() (rateTx, rateRx int64) {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	return lastRateTx, lastRateRx
}

// runTrafficSync runs the traffic sync loop
func runTrafficSync(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Track totals for rate calculation
	var prevTotalTx, prevTotalRx int64
	prevTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncTrafficStats(&prevTotalTx, &prevTotalRx, &prevTime)
		}
	}
}

// syncTrafficStats syncs WireGuard traffic to database
func syncTrafficStats(prevTotalTx, prevTotalRx *int64, prevTime *time.Time) {
	db, err := database.GetDB()
	if err != nil {
		return
	}

	// Get current WireGuard transfer stats
	transfers, err := GetWgTransfer()
	if err != nil {
		return
	}

	// Build public key to transfer map
	transferMap := make(map[string]PeerTransfer)
	for _, t := range transfers {
		transferMap[t.PublicKey] = t
	}

	// Get clients with their public keys and last readings
	rows, err := db.Query(`
		SELECT id, public_key, last_tx, last_rx, total_tx, total_rx
		FROM vpn_clients
		WHERE type = 'wireguard' AND public_key IS NOT NULL AND public_key != ''
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	var totalTx, totalRx int64

	for rows.Next() {
		var id int
		var pubKey string
		var lastTx, lastRx, totalClientTx, totalClientRx int64
		if err := rows.Scan(&id, &pubKey, &lastTx, &lastRx, &totalClientTx, &totalClientRx); err != nil {
			continue
		}

		transfer, ok := transferMap[pubKey]
		if !ok {
			// Peer not currently connected, keep existing totals
			totalTx += totalClientTx
			totalRx += totalClientRx
			continue
		}

		// Calculate deltas
		var deltaTx, deltaRx int64

		if transfer.Tx >= lastTx {
			// Normal case: current >= last
			deltaTx = transfer.Tx - lastTx
		}
		// If current < last, WireGuard was restarted, don't add delta

		if transfer.Rx >= lastRx {
			deltaRx = transfer.Rx - lastRx
		}

		// Update database
		newTotalTx := totalClientTx + deltaTx
		newTotalRx := totalClientRx + deltaRx

		db.Exec(`
			UPDATE vpn_clients
			SET total_tx = ?, total_rx = ?, last_tx = ?, last_rx = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, newTotalTx, newTotalRx, transfer.Tx, transfer.Rx, id)

		totalTx += newTotalTx
		totalRx += newTotalRx
	}

	// Calculate rates
	now := time.Now()
	elapsed := now.Sub(*prevTime).Seconds()
	if elapsed > 0 && *prevTotalTx > 0 {
		trafficMu.Lock()
		lastRateTx = int64(float64(totalTx-*prevTotalTx) / elapsed)
		lastRateRx = int64(float64(totalRx-*prevTotalRx) / elapsed)
		if lastRateTx < 0 {
			lastRateTx = 0
		}
		if lastRateRx < 0 {
			lastRateRx = 0
		}
		trafficMu.Unlock()
	}

	*prevTotalTx = totalTx
	*prevTotalRx = totalRx
	*prevTime = now
}
