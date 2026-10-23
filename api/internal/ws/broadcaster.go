package ws

import (
	"log"
	"sync"
	"time"

	"api/internal/docker"
)

// DockerLogEntry represents a single log line from Docker
type DockerLogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Stream    string `json:"stream"`
}

// DockerLogStreamer interface for streaming Docker logs
type DockerLogStreamer interface {
	StreamLogs(containerName string, onLog func(DockerLogEntry), stop <-chan struct{}) error
}

// OverviewStats represents combined stats for the overview dashboard
type OverviewStats struct {
	System     SystemStats        `json:"system"`
	Traffic    TrafficStats       `json:"traffic"`
	Services   []ServiceHealth    `json:"services,omitempty"`
	DockerInfo *docker.DockerInfo `json:"dockerInfo,omitempty"`
	DiskUsage  *docker.DiskUsage  `json:"diskUsage,omitempty"`
	Security   *SecurityStats     `json:"security,omitempty"`
	Sessions   []SessionInfo      `json:"sessions,omitempty"` // live WG "online now" — read by PeersCard
}

// SessionInfo mirrors the /api/wg/sessions JSON so the Overview "Online now" widget
// reads it from the stats push instead of polling.
type SessionInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Endpoint      string `json:"endpoint"`
	EndpointIP    string `json:"endpointIp"`
	LastHandshake string `json:"lastHandshake"`
	Rx            int64  `json:"rx"`
	Tx            int64  `json:"tx"`
}

// SecurityStats is the last-hour security summary pushed on the stats stream so the
// Overview security widgets don't each poll. Fields mirror the /api/fw/overview,
// /api/fw/layers and public-visitors JSON shapes so the widgets read them as-is.
type SecurityStats struct {
	Overview interface{} `json:"overview"` // /api/fw/overview shape
	Layers   interface{} `json:"layers"`   // /api/fw/layers shape (last hour)
	Visitors interface{} `json:"visitors"` // { unique_visitors, countries }
}

// ServiceHealth is one core service's up/down status for the dashboard health row.
type ServiceHealth struct {
	Key    string `json:"key"`    // stable identifier, e.g. "traefik"
	Name   string `json:"name"`   // display label, e.g. "Traefik"
	Status string `json:"status"` // "up" | "down"
}

// SystemStats contains Go runtime metrics
type SystemStats struct {
	Uptime       int64  `json:"uptime"`
	MemAlloc     uint64 `json:"mem_alloc"`
	MemSys       uint64 `json:"mem_sys"`
	NumGoroutine int    `json:"num_goroutine"`
	NumGC        uint32 `json:"num_gc"`
	WsClients    int    `json:"ws_clients"`
}

// TrafficStats contains VPN traffic metrics
type TrafficStats struct {
	TotalTx int64             `json:"total_tx"`
	TotalRx int64             `json:"total_rx"`
	RateTx  int64             `json:"rate_tx"`
	RateRx  int64             `json:"rate_rx"`
	ByPeer  []PeerTrafficInfo `json:"by_peer"`
}

// PeerTrafficInfo contains traffic for a single peer
type PeerTrafficInfo struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Tx   int64  `json:"tx"`
	Rx   int64  `json:"rx"`
}

// NodeStatusInfo represents a single node's status
type NodeStatusInfo struct {
	Name   string
	Online bool
}

// NodeStatusChangeFunc is called when node status changes (for push notifications)
type NodeStatusChangeFunc func(nodeName string, online bool)

var (
	// syncNodesCallback refreshes node data from Headscale/WireGuard
	syncNodesCallback func()
	// getNodeStatusListCallback returns individual node status for change detection
	getNodeStatusListCallback func() []NodeStatusInfo
	// nodeStatusChangeCallback is called when a node goes online/offline
	nodeStatusChangeCallback NodeStatusChangeFunc
	// getDockerContainersCallback returns current docker containers
	getDockerContainersCallback func() []docker.Container
	// getContainerStatsCallback returns live per-container resource stats
	getContainerStatsCallback func() []docker.ContainerStats
	// getOverviewStatsCallback returns combined stats for dashboard
	getOverviewStatsCallback func() OverviewStats
	// dockerLogStreamer for streaming container logs
	dockerLogStreamer DockerLogStreamer
	callbackMu        sync.RWMutex

	// lastNodeStatus stores previous individual node status for change detection
	lastNodeStatus   map[string]bool // node name -> online
	lastNodeStatusMu sync.RWMutex

	// lastDockerContainers stores previous container states for change detection
	lastDockerContainers   []docker.Container
	lastDockerContainersMu sync.RWMutex

	// statusTicker for periodic status checks (guarded by statusMu)
	statusMu     sync.Mutex
	statusTicker *time.Ticker
	stopStatus   chan struct{}
)

// SetNodeStatusProvider sets the callbacks for syncing nodes and listing their status
// This avoids circular imports (vpn -> ws -> vpn)
func SetNodeStatusProvider(syncFn func(), statusListFn func() []NodeStatusInfo) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	syncNodesCallback = syncFn
	getNodeStatusListCallback = statusListFn
}

// SetNodeStatusChangeCallback sets the callback for node status change notifications
func SetNodeStatusChangeCallback(fn NodeStatusChangeFunc) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	nodeStatusChangeCallback = fn
}

// SetDockerProvider sets the callback for getting docker containers
func SetDockerProvider(containersFn func() []docker.Container) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	getDockerContainersCallback = containersFn
}

// SetContainerStatsProvider sets the callback for live per-container stats
func SetContainerStatsProvider(statsFn func() []docker.ContainerStats) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	getContainerStatsCallback = statsFn
}

// SetDockerLogStreamer sets the docker log streamer
func SetDockerLogStreamer(streamer DockerLogStreamer) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	dockerLogStreamer = streamer
}

// SetOverviewStatsProvider sets the callback for getting overview stats
func SetOverviewStatsProvider(statsFn func() OverviewStats) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	getOverviewStatsCallback = statsFn
}

// GetDockerLogStreamer returns the docker log streamer
func GetDockerLogStreamer() DockerLogStreamer {
	callbackMu.RLock()
	defer callbackMu.RUnlock()
	return dockerLogStreamer
}

// safeGo runs fn in a new goroutine, recovering from any panic. Callback code
// (e.g. web-push notification handlers) runs here; without recover a single panic
// in that path would crash the entire backend process, not just the notification.
func safeGo(fn func()) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("ws: recovered from panic in goroutine: %v", rec)
			}
		}()
		fn()
	}()
}

// safeRun runs fn synchronously with panic recovery, so one failed status-checker
// tick logs and the periodic loop keeps running instead of dying permanently.
func safeRun(name string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("ws: recovered from panic in %s: %v", name, rec)
		}
	}()
	fn()
}

// StartStatusChecker starts the background status polling (nodes + docker)
func StartStatusChecker(interval time.Duration) {
	statusMu.Lock()
	if statusTicker != nil {
		statusMu.Unlock()
		return // Already running
	}
	stop := make(chan struct{})
	ticker := time.NewTicker(interval)
	stopStatus, statusTicker = stop, ticker
	statusMu.Unlock()

	// Use the local `ticker`/`stop` (not the package vars) so the goroutine never
	// races with Start/Stop mutating them.
	go func() {
		log.Printf("Status checker started (interval: %v)", interval)
		for {
			select {
			case <-ticker.C:
				safeRun("status checker tick", checkAndBroadcastStatus)
			case <-stop:
				ticker.Stop()
				log.Println("Status checker stopped")
				return
			}
		}
	}()
}

// StopStatusChecker stops the background status polling
func StopStatusChecker() {
	statusMu.Lock()
	defer statusMu.Unlock()
	if stopStatus != nil {
		close(stopStatus)
		stopStatus, statusTicker = nil, nil // nil both: double-close safe + restartable
	}
}

// checkAndBroadcastStatus syncs data and broadcasts if changed
func checkAndBroadcastStatus() {
	if serviceInstance == nil || serviceInstance.hub == nil {
		return
	}

	// Sync VPN nodes, notify on status changes
	checkNodeStatus()

	// Check docker containers
	checkAndBroadcastDocker()

	// Check overview stats (always broadcast to stats channel if subscribers)
	checkAndBroadcastOverviewStats()

	// Live per-container resource stats (runs last: the fan-out blocks ~1s, so
	// keep it off the critical path of the broadcasts above).
	checkAndBroadcastContainerStats()
}

// checkAndBroadcastContainerStats broadcasts live per-container resource usage.
// Gated on subscribers so the (blocking) docker stats fan-out only runs while
// the Docker page is open.
func checkAndBroadcastContainerStats() {
	if serviceInstance.hub.ChannelSubscriberCount("container_stats") == 0 {
		return
	}
	callbackMu.RLock()
	fn := getContainerStatsCallback
	callbackMu.RUnlock()
	if fn == nil {
		return
	}
	serviceInstance.hub.Broadcast("container_stats", map[string]interface{}{
		"containers": fn(),
	})
}

// checkAndBroadcastOverviewStats broadcasts overview stats to stats channel
func checkAndBroadcastOverviewStats() {
	if serviceInstance.hub.ChannelSubscriberCount("stats") == 0 {
		return
	}

	callbackMu.RLock()
	statsFn := getOverviewStatsCallback
	callbackMu.RUnlock()

	if statsFn == nil {
		return
	}

	stats := statsFn()
	serviceInstance.hub.Broadcast("stats", stats)
}

// checkNodeStatus refreshes VPN node data and reports nodes that went online/offline (push
// notifications). Client counts live on the "clients" channel, not here.
func checkNodeStatus() {
	callbackMu.RLock()
	syncFn := syncNodesCallback
	statusListFn := getNodeStatusListCallback
	statusChangeFn := nodeStatusChangeCallback
	callbackMu.RUnlock()

	if syncFn != nil {
		syncFn()
	}
	if statusListFn != nil && statusChangeFn != nil {
		checkNodeStatusChanges(statusListFn(), statusChangeFn)
	}
}

// checkNodeStatusChanges detects which nodes changed status and calls the callback
func checkNodeStatusChanges(current []NodeStatusInfo, onChange NodeStatusChangeFunc) {
	lastNodeStatusMu.Lock()
	defer lastNodeStatusMu.Unlock()

	// Initialize on first run
	if lastNodeStatus == nil {
		lastNodeStatus = make(map[string]bool)
		for _, node := range current {
			lastNodeStatus[node.Name] = node.Online
		}
		return
	}

	// Build current status map
	currentStatus := make(map[string]bool)
	for _, node := range current {
		currentStatus[node.Name] = node.Online

		// Check if status changed
		if prev, exists := lastNodeStatus[node.Name]; exists {
			if prev != node.Online {
				// Status changed - notify
				changedName, changedOnline := node.Name, node.Online
				safeGo(func() { onChange(changedName, changedOnline) })
			}
		}
		// Note: new nodes don't trigger notification (avoid spam on first sync)
	}

	// Update last status
	lastNodeStatus = currentStatus
}

// checkAndBroadcastDocker checks docker status and broadcasts if changed
func checkAndBroadcastDocker() {
	if serviceInstance.hub.ChannelSubscriberCount("docker") == 0 {
		return
	}

	callbackMu.RLock()
	containersFn := getDockerContainersCallback
	callbackMu.RUnlock()

	if containersFn == nil {
		return
	}

	containers := containersFn()

	// Compare with last containers
	lastDockerContainersMu.RLock()
	changed := dockerContainersChanged(lastDockerContainers, containers)
	lastDockerContainersMu.RUnlock()

	if changed {
		lastDockerContainersMu.Lock()
		lastDockerContainers = containers
		lastDockerContainersMu.Unlock()

		log.Printf("Docker status changed, broadcasting %d containers", len(containers))
		serviceInstance.hub.Broadcast("docker", map[string]interface{}{
			"containers": containers,
		})
	}
}

// dockerContainersChanged checks if container states have changed
func dockerContainersChanged(old, new []docker.Container) bool {
	if len(old) != len(new) {
		return true
	}
	oldMap := make(map[string]docker.Container)
	for _, c := range old {
		oldMap[c.ID] = c
	}
	for _, c := range new {
		if prev, ok := oldMap[c.ID]; !ok || prev.State != c.State || prev.Status != c.Status {
			return true
		}
	}
	return false
}

// GetCurrentOverviewStats returns current overview stats (for sending on subscribe)
func GetCurrentOverviewStats() *OverviewStats {
	callbackMu.RLock()
	statsFn := getOverviewStatsCallback
	callbackMu.RUnlock()

	if statsFn == nil {
		return nil
	}
	stats := statsFn()
	return &stats
}

// GetCurrentDockerContainers returns current docker containers (for sending on subscribe)
func GetCurrentDockerContainers() []docker.Container {
	callbackMu.RLock()
	containersFn := getDockerContainersCallback
	callbackMu.RUnlock()

	if containersFn == nil {
		return nil
	}
	return containersFn()
}
