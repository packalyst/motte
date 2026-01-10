package stats

import (
	"runtime"
	"sync"
	"time"
)

var (
	startTime  time.Time
	startOnce  sync.Once
	wsClientsFn func() int
)

// SystemStats contains Go runtime and system metrics
type SystemStats struct {
	Uptime       int64  `json:"uptime"`        // seconds since start
	MemAlloc     uint64 `json:"mem_alloc"`     // bytes allocated on heap
	MemSys       uint64 `json:"mem_sys"`       // bytes obtained from OS
	NumGoroutine int    `json:"num_goroutine"` // current goroutine count
	NumGC        uint32 `json:"num_gc"`        // completed GC cycles
	WsClients    int    `json:"ws_clients"`    // connected WebSocket clients
}

// TrafficStats contains VPN traffic metrics
type TrafficStats struct {
	TotalTx int64        `json:"total_tx"` // total bytes sent
	TotalRx int64        `json:"total_rx"` // total bytes received
	RateTx  int64        `json:"rate_tx"`  // bytes/sec sent
	RateRx  int64        `json:"rate_rx"`  // bytes/sec received
	ByPeer  []PeerTraffic `json:"by_peer"` // per-peer breakdown
}

// PeerTraffic contains traffic for a single peer
type PeerTraffic struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Tx   int64  `json:"tx"`
	Rx   int64  `json:"rx"`
}

// NodeStats contains VPN node counts
type NodeStats struct {
	Online  int `json:"online"`
	Offline int `json:"offline"`
	Total   int `json:"total"`
}

// OverviewStats is the combined stats payload for WebSocket
type OverviewStats struct {
	System  SystemStats  `json:"system"`
	Traffic TrafficStats `json:"traffic"`
	Nodes   NodeStats    `json:"nodes"`
}

// Init records the start time (call once at startup)
func Init() {
	startOnce.Do(func() {
		startTime = time.Now()
	})
}

// SetWsClientsProvider sets the function to get WebSocket client count
func SetWsClientsProvider(fn func() int) {
	wsClientsFn = fn
}

// GetSystemStats returns current system metrics
func GetSystemStats() SystemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	wsClients := 0
	if wsClientsFn != nil {
		wsClients = wsClientsFn()
	}

	return SystemStats{
		Uptime:       int64(time.Since(startTime).Seconds()),
		MemAlloc:     m.Alloc,
		MemSys:       m.Sys,
		NumGoroutine: runtime.NumGoroutine(),
		NumGC:        m.NumGC,
		WsClients:    wsClients,
	}
}

// GetUptime returns seconds since start
func GetUptime() int64 {
	return int64(time.Since(startTime).Seconds())
}
