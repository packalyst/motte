package stats

import (
	"runtime"
	"sync"
	"time"
)

var (
	startTime   time.Time
	startOnce   sync.Once
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
