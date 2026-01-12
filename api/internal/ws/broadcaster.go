package ws

import (
	"log"
	"sync"
	"time"

	"api/internal/docker"
)

// NodeStats represents VPN node statistics for the dashboard
type NodeStats struct {
	Online  int `json:"online"`
	Offline int `json:"offline"`
	HsNodes int `json:"hsNodes"`
	WgPeers int `json:"wgPeers"`
}

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
	System      SystemStats       `json:"system"`
	Traffic     TrafficStats      `json:"traffic"`
	Nodes       NodeStats         `json:"nodes"`
	DockerInfo  *docker.DockerInfo `json:"dockerInfo,omitempty"`
	DiskUsage   *docker.DiskUsage  `json:"diskUsage,omitempty"`
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
	// getNodeStatsCallback returns current node statistics
	getNodeStatsCallback func() NodeStats
	// getNodeStatusListCallback returns individual node status for change detection
	getNodeStatusListCallback func() []NodeStatusInfo
	// nodeStatusChangeCallback is called when a node goes online/offline
	nodeStatusChangeCallback NodeStatusChangeFunc
	// getDockerContainersCallback returns current docker containers
	getDockerContainersCallback func() []docker.Container
	// getOverviewStatsCallback returns combined stats for dashboard
	getOverviewStatsCallback func() OverviewStats
	// dockerLogStreamer for streaming container logs
	dockerLogStreamer DockerLogStreamer
	callbackMu        sync.RWMutex

	// lastNodeStats stores previous stats for change detection
	lastNodeStats   NodeStats
	lastNodeStatsMu sync.RWMutex

	// lastNodeStatus stores previous individual node status for change detection
	lastNodeStatus   map[string]bool // node name -> online
	lastNodeStatusMu sync.RWMutex

	// lastDockerContainers stores previous container states for change detection
	lastDockerContainers   []docker.Container
	lastDockerContainersMu sync.RWMutex

	// statusTicker for periodic status checks
	statusTicker *time.Ticker
	stopStatus   chan struct{}
)

// SetNodeStatsProvider sets the callbacks for syncing and getting node stats
// This avoids circular imports (vpn -> ws -> vpn)
func SetNodeStatsProvider(syncFn func(), statsFn func() NodeStats, statusListFn func() []NodeStatusInfo) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	syncNodesCallback = syncFn
	getNodeStatsCallback = statsFn
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

// StartStatusChecker starts the background status polling (nodes + docker)
func StartStatusChecker(interval time.Duration) {
	if statusTicker != nil {
		return // Already running
	}

	stopStatus = make(chan struct{})
	statusTicker = time.NewTicker(interval)

	go func() {
		log.Printf("Status checker started (interval: %v)", interval)
		for {
			select {
			case <-statusTicker.C:
				checkAndBroadcastStatus()
			case <-stopStatus:
				statusTicker.Stop()
				log.Println("Status checker stopped")
				return
			}
		}
	}()
}

// StopStatusChecker stops the background status polling
func StopStatusChecker() {
	if stopStatus != nil {
		close(stopStatus)
		statusTicker = nil
	}
}

// checkAndBroadcastStatus syncs data and broadcasts if changed
func checkAndBroadcastStatus() {
	if serviceInstance == nil || serviceInstance.hub == nil {
		return
	}

	// Check node stats
	checkAndBroadcastNodes()

	// Check docker containers
	checkAndBroadcastDocker()

	// Check overview stats (always broadcast to stats channel if subscribers)
	checkAndBroadcastOverviewStats()
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

// checkAndBroadcastNodes checks node status and broadcasts if changed
func checkAndBroadcastNodes() {
	// Skip if no subscribers for either channel
	hasInfoSubscribers := serviceInstance.hub.ChannelSubscriberCount("general_info") > 0
	hasNodesSubscribers := serviceInstance.hub.ChannelSubscriberCount("nodes_updated") > 0

	// Call sync to refresh data from Headscale/WireGuard
	callbackMu.RLock()
	syncFn := syncNodesCallback
	statsFn := getNodeStatsCallback
	statusListFn := getNodeStatusListCallback
	statusChangeFn := nodeStatusChangeCallback
	callbackMu.RUnlock()

	if syncFn != nil {
		syncFn()
	}

	// Check individual node status changes for push notifications
	if statusListFn != nil && statusChangeFn != nil {
		checkNodeStatusChanges(statusListFn(), statusChangeFn)
	}

	// Skip WebSocket broadcasts if no subscribers
	if !hasInfoSubscribers && !hasNodesSubscribers {
		return
	}

	if statsFn == nil {
		return
	}

	// Get current stats
	stats := statsFn()

	// Compare with last stats
	lastNodeStatsMu.RLock()
	statsChanged := stats != lastNodeStats
	nodeCountChanged := stats.HsNodes != lastNodeStats.HsNodes || stats.WgPeers != lastNodeStats.WgPeers
	lastNodeStatsMu.RUnlock()

	if statsChanged {
		lastNodeStatsMu.Lock()
		lastNodeStats = stats
		lastNodeStatsMu.Unlock()

		if hasInfoSubscribers {
			log.Printf("Node status changed, broadcasting: online=%d, offline=%d, hs=%d, wg=%d",
				stats.Online, stats.Offline, stats.HsNodes, stats.WgPeers)
			serviceInstance.hub.Broadcast("general_info", map[string]interface{}{
				"event": "stats",
				"data":  stats,
			})
		}

		// Notify nodes_updated if node counts changed
		if nodeCountChanged && hasNodesSubscribers {
			log.Println("Broadcasting nodes_updated notification")
			serviceInstance.hub.Broadcast("nodes_updated", nil)
		}
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
				go onChange(node.Name, node.Online)
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

// BroadcastNodeStats broadcasts current node stats to subscribers
// Called when nodes change (create, delete, sync)
func BroadcastNodeStats() {
	if serviceInstance == nil || serviceInstance.hub == nil {
		return
	}

	callbackMu.RLock()
	statsFn := getNodeStatsCallback
	callbackMu.RUnlock()

	if statsFn == nil {
		return
	}

	stats := statsFn()

	// Check if node counts changed (not just online/offline status)
	lastNodeStatsMu.RLock()
	nodeCountChanged := stats.HsNodes != lastNodeStats.HsNodes || stats.WgPeers != lastNodeStats.WgPeers
	lastNodeStatsMu.RUnlock()

	// Update last stats
	lastNodeStatsMu.Lock()
	lastNodeStats = stats
	lastNodeStatsMu.Unlock()

	// Broadcast stats if there are subscribers
	if serviceInstance.hub.ChannelSubscriberCount("general_info") > 0 {
		log.Printf("Broadcasting node stats: online=%d, offline=%d, hs=%d, wg=%d",
			stats.Online, stats.Offline, stats.HsNodes, stats.WgPeers)
		serviceInstance.hub.Broadcast("general_info", map[string]interface{}{
			"event": "stats",
			"data":  stats,
		})
	}

	// Notify nodes_updated subscribers if node counts changed
	if nodeCountChanged && serviceInstance.hub.ChannelSubscriberCount("nodes_updated") > 0 {
		log.Println("Broadcasting nodes_updated notification")
		serviceInstance.hub.Broadcast("nodes_updated", nil)
	}
}

// GetCurrentNodeStats returns current node stats (for sending on subscribe)
func GetCurrentNodeStats() NodeStats {
	callbackMu.RLock()
	statsFn := getNodeStatsCallback
	callbackMu.RUnlock()

	if statsFn == nil {
		return NodeStats{}
	}
	return statsFn()
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

// BroadcastTraffic broadcasts traffic data to subscribers
func BroadcastTraffic(traffic interface{}) {
	Broadcast("traffic", traffic)
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
