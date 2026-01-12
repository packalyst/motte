package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"api/internal/router"
)

// validContainerName matches valid Docker container names (alphanumeric, underscore, dash, dot)
var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// validImageName matches valid Docker image names (registry/namespace/name:tag or name@sha256:digest)
var validImageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_./:@-]*$`)

// Service handles Docker operations via Unix socket or TCP
type Service struct {
	host   string // tcp://host:port or unix:///path
	client *http.Client

	// Cached overview stats (disk usage is slow)
	overviewMu        sync.RWMutex
	cachedInfo        *DockerInfo
	cachedDiskUsage   *DiskUsage
	cacheTime         time.Time
	cacheTTL          time.Duration
	cacheRefreshing   bool
}

// Container represents a Docker container
type Container struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	ImageID string            `json:"imageId"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Created int64             `json:"created"`
	Ports   []Port            `json:"ports"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// Port represents a container port mapping
type Port struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort,omitempty"`
	Type        string `json:"type"`
}

// New creates a new Docker service
func New() *Service {
	// Check DOCKER_HOST env var for TCP or Unix socket
	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	var client *http.Client

	if strings.HasPrefix(dockerHost, "tcp://") {
		// TCP connection to docker socket proxy
		tcpAddr := strings.TrimPrefix(dockerHost, "tcp://")
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("tcp", tcpAddr)
				},
			},
			Timeout: 30 * time.Second,
		}
		log.Printf("Docker service using TCP: %s", tcpAddr)
	} else {
		// Unix socket (default)
		socketPath := strings.TrimPrefix(dockerHost, "unix://")
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
			Timeout: 30 * time.Second,
		}
		log.Printf("Docker service using Unix socket: %s", socketPath)
	}

	return &Service{
		host:     dockerHost,
		client:   client,
		cacheTTL: 30 * time.Second, // Cache docker overview stats for 30 seconds
	}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetContainers": s.handleGetContainers,
		"GetContainer":  s.handleGetContainer,
		"Restart":       s.handleRestart,
		"Stop":          s.handleStop,
		"Start":         s.handleStart,
		"AnalyzeImage":  s.handleAnalyzeImage,
	}
}

// ImageLayer represents a layer in the image with explanation
type ImageLayer struct {
	Category string `json:"category"`
	Size     int64  `json:"size"`
	SizeHR   string `json:"sizeHR"`
	Purpose  string `json:"purpose"`
	Command  string `json:"command,omitempty"`
}

// ImageAnalysis represents the full image analysis
type ImageAnalysis struct {
	Image     string       `json:"image"`
	TotalSize int64        `json:"totalSize"`
	TotalHR   string       `json:"totalHR"`
	Layers    []ImageLayer `json:"layers"`
}

// doRequest performs a request to Docker API
func (s *Service) doRequest(method, path string) (*http.Response, error) {
	req, err := http.NewRequest(method, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	return s.client.Do(req)
}

// GetContainers returns list of containers
func (s *Service) GetContainers() ([]Container, error) {
	resp, err := s.doRequest("GET", "/v1.44/containers/json?all=true")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Docker: %w", err)
	}
	defer resp.Body.Close()

	var rawContainers []struct {
		ID      string `json:"Id"`
		Names   []string
		Image   string
		ImageID string
		State   string
		Status  string
		Created int64
		Ports   []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
		Labels map[string]string
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawContainers); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	containers := make([]Container, 0, len(rawContainers))
	for _, c := range rawContainers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		ports := make([]Port, len(c.Ports))
		for i, p := range c.Ports {
			ports[i] = Port{
				IP:          p.IP,
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
			}
		}

		// ImageID comes as sha256:abc123..., extract the short hash
		imageID := strings.TrimPrefix(c.ImageID, "sha256:")
		if len(imageID) > 12 {
			imageID = imageID[:12]
		}

		containers = append(containers, Container{
			ID:      c.ID[:12],
			Name:    name,
			Image:   c.Image,
			ImageID: imageID,
			State:   c.State,
			Status:  c.Status,
			Created: c.Created,
			Ports:   ports,
		})
	}

	return containers, nil
}

// handleGetContainers returns list of containers
func (s *Service) handleGetContainers(w http.ResponseWriter, r *http.Request) {
	containers, err := s.GetContainers()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]interface{}{
		"containers": containers,
	})
}

// handleGetContainer returns details for a specific container
func (s *Service) handleGetContainer(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	resp, err := s.doRequest("GET", "/v1.44/containers/"+name+"/json")
	if err != nil {
		router.JSONError(w, "Failed to get container: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	var container map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&container); err != nil {
		router.JSONError(w, "Failed to parse response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, container)
}

// LogEntry represents a single log line
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Stream    string `json:"stream"` // "stdout" or "stderr"
}

// StreamLogs streams logs from a container, calling onLog for each line
// Returns when stop channel is closed or on error
func (s *Service) StreamLogs(containerName string, onLog func(LogEntry), stop <-chan struct{}) error {
	if !validContainerName.MatchString(containerName) {
		return fmt.Errorf("invalid container name")
	}

	// Get logs with follow=true for streaming, since=0 to start from now
	resp, err := s.doRequest("GET", fmt.Sprintf("/v1.44/containers/%s/logs?stdout=true&stderr=true&follow=true&tail=50&timestamps=true", containerName))
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	if resp.StatusCode == 404 {
		resp.Body.Close()
		return fmt.Errorf("container not found")
	}

	// Close the response body when stop is signaled to unblock the reader
	done := make(chan struct{})
	go func() {
		select {
		case <-stop:
			resp.Body.Close()
		case <-done:
		}
	}()
	defer func() {
		close(done)
		resp.Body.Close()
	}()

	reader := bufio.NewReader(resp.Body)
	for {
		// Docker log format: 8-byte header + message
		// Header: [stream_type(1), 0, 0, 0, size(4)]
		header := make([]byte, 8)
		_, err := reader.Read(header)
		if err != nil {
			return nil // Connection closed or stop signaled
		}

		// Get stream type from first byte
		streamType := "stdout"
		if header[0] == 2 {
			streamType = "stderr"
		}

		// Get message size from bytes 4-7 (big endian)
		size := int(header[4])<<24 | int(header[5])<<16 | int(header[6])<<8 | int(header[7])
		if size == 0 {
			continue
		}

		// Read message
		msg := make([]byte, size)
		_, err = reader.Read(msg)
		if err != nil {
			return nil
		}

		message := strings.TrimSpace(string(msg))
		if message == "" {
			continue
		}

		// Parse timestamp if present
		entry := LogEntry{Stream: streamType}
		parts := strings.SplitN(message, " ", 2)
		if len(parts) == 2 && len(parts[0]) > 20 {
			entry.Timestamp = parts[0]
			entry.Message = parts[1]
		} else {
			entry.Message = message
		}

		onLog(entry)
	}
}

// handleRestart restarts a container
func (s *Service) handleRestart(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	name = strings.TrimSuffix(name, "/restart")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	log.Printf("Restarting container: %s", name)

	resp, err := s.doRequest("POST", "/v1.44/containers/"+name+"/restart?t=10")
	if err != nil {
		router.JSONError(w, "Failed to restart container: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	if resp.StatusCode != 204 {
		router.JSONError(w, "Failed to restart container", resp.StatusCode)
		return
	}

	log.Printf("Container %s restarted successfully", name)
	router.JSON(w, map[string]string{"status": "restarted", "container": name})
}

// handleStop stops a container
func (s *Service) handleStop(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	name = strings.TrimSuffix(name, "/stop")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	log.Printf("Stopping container: %s", name)

	resp, err := s.doRequest("POST", "/v1.44/containers/"+name+"/stop?t=10")
	if err != nil {
		router.JSONError(w, "Failed to stop container: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	if resp.StatusCode == 304 {
		router.JSON(w, map[string]string{"status": "already_stopped", "container": name})
		return
	}

	if resp.StatusCode != 204 {
		router.JSONError(w, "Failed to stop container", resp.StatusCode)
		return
	}

	log.Printf("Container %s stopped successfully", name)
	router.JSON(w, map[string]string{"status": "stopped", "container": name})
}

// handleStart starts a container
func (s *Service) handleStart(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	name = strings.TrimSuffix(name, "/start")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	log.Printf("Starting container: %s", name)

	resp, err := s.doRequest("POST", "/v1.44/containers/"+name+"/start")
	if err != nil {
		router.JSONError(w, "Failed to start container: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	if resp.StatusCode == 304 {
		router.JSON(w, map[string]string{"status": "already_running", "container": name})
		return
	}

	if resp.StatusCode != 204 {
		router.JSONError(w, "Failed to start container", resp.StatusCode)
		return
	}

	log.Printf("Container %s started successfully", name)
	router.JSON(w, map[string]string{"status": "started", "container": name})
}

// handleAnalyzeImage analyzes an image and returns layer breakdown
func (s *Service) handleAnalyzeImage(w http.ResponseWriter, r *http.Request) {
	// Get image name from path: /api/docker/images/{name}/analyze
	path := r.URL.Path
	name := strings.TrimPrefix(path, "/api/docker/images/")
	name = strings.TrimSuffix(name, "/analyze")

	if name == "" {
		router.JSONError(w, "Image name required", http.StatusBadRequest)
		return
	}
	if !validImageName.MatchString(name) {
		router.JSONError(w, "Invalid image name", http.StatusBadRequest)
		return
	}

	analysis, err := s.AnalyzeImage(name)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, analysis)
}

// AnalyzeImage returns a detailed breakdown of image layers
func (s *Service) AnalyzeImage(imageName string) (*ImageAnalysis, error) {
	// Get image info for total size
	resp, err := s.doRequest("GET", "/v1.44/images/"+imageName+"/json")
	if err != nil {
		return nil, fmt.Errorf("failed to get image info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("image not found: %s", imageName)
	}

	var imageInfo struct {
		Size int64 `json:"Size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&imageInfo); err != nil {
		return nil, fmt.Errorf("failed to parse image info: %w", err)
	}

	// Get image history for layers
	histResp, err := s.doRequest("GET", "/v1.44/images/"+imageName+"/history")
	if err != nil {
		return nil, fmt.Errorf("failed to get image history: %w", err)
	}
	defer histResp.Body.Close()

	var history []struct {
		Created   int64    `json:"Created"`
		CreatedBy string   `json:"CreatedBy"`
		Size      int64    `json:"Size"`
		Tags      []string `json:"Tags"`
	}
	if err := json.NewDecoder(histResp.Body).Decode(&history); err != nil {
		return nil, fmt.Errorf("failed to parse history: %w", err)
	}

	// Process and group layers by category
	categoryMap := make(map[string]*ImageLayer)
	categoryOrder := []string{} // Preserve order of first appearance

	for _, h := range history {
		if h.Size == 0 {
			continue
		}

		category, purpose := categorizeLayer(h.CreatedBy)

		if existing, ok := categoryMap[category]; ok {
			// Add to existing category
			existing.Size += h.Size
			existing.SizeHR = formatBytes(existing.Size)
		} else {
			// New category
			categoryMap[category] = &ImageLayer{
				Category: category,
				Size:     h.Size,
				SizeHR:   formatBytes(h.Size),
				Purpose:  purpose,
			}
			categoryOrder = append(categoryOrder, category)
		}
	}

	// Build layers slice in order, sorted by size (largest first)
	layers := make([]ImageLayer, 0, len(categoryMap))
	for _, cat := range categoryOrder {
		layers = append(layers, *categoryMap[cat])
	}

	// Sort by size descending
	sort.Slice(layers, func(i, j int) bool {
		return layers[i].Size > layers[j].Size
	})

	// Calculate actual total from layers (more accurate than image size which includes metadata)
	var layersTotal int64
	for _, l := range layers {
		layersTotal += l.Size
	}

	return &ImageAnalysis{
		Image:     imageName,
		TotalSize: layersTotal,
		TotalHR:   formatBytes(layersTotal),
		Layers:    layers,
	}, nil
}

// categorizeLayer analyzes a Dockerfile command and returns category + purpose
func categorizeLayer(cmd string) (category, purpose string) {
	cmdLower := strings.ToLower(cmd)

	// Base image patterns
	if strings.Contains(cmdLower, "from") ||
		strings.Contains(cmdLower, "/bin/sh -c #(nop)") && (strings.Contains(cmdLower, "add") || strings.Contains(cmdLower, "copy")) && strings.Contains(cmdLower, "in /") {
		return "Base OS", "Base operating system image"
	}

	// Package managers - APT
	if strings.Contains(cmdLower, "apt-get") && strings.Contains(cmdLower, "install") {
		packages := extractPackages(cmd, "apt-get")
		if packages != "" {
			return "System packages", packages
		}
		return "System packages", "Installed via apt-get"
	}

	// Package managers - APK (Alpine)
	if strings.Contains(cmdLower, "apk add") {
		packages := extractPackages(cmd, "apk")
		if packages != "" {
			return "System packages", packages
		}
		return "System packages", "Installed via apk"
	}

	// Package managers - YUM/DNF
	if (strings.Contains(cmdLower, "yum install") || strings.Contains(cmdLower, "dnf install")) {
		return "System packages", "Installed via yum/dnf"
	}

	// Node.js
	if strings.Contains(cmdLower, "npm install") || strings.Contains(cmdLower, "npm ci") {
		return "Node modules", "JavaScript dependencies"
	}
	if strings.Contains(cmdLower, "yarn") {
		return "Node modules", "JavaScript dependencies (yarn)"
	}

	// Go
	if strings.Contains(cmdLower, "go build") {
		return "Go build", "Compiled Go binary"
	}
	if strings.Contains(cmdLower, "go mod") {
		return "Go modules", "Go dependencies"
	}

	// Python
	if strings.Contains(cmdLower, "pip install") {
		return "Python packages", "Python dependencies"
	}

	// COPY commands
	if strings.Contains(cmdLower, "copy") {
		return categorizeCopy(cmd)
	}

	// ADD commands
	if strings.Contains(cmdLower, "add") && !strings.Contains(cmdLower, "apk add") {
		return "Added files", "Files added to image"
	}

	// Nginx specific
	if strings.Contains(cmdLower, "nginx") && (strings.Contains(cmdLower, "apkarch") || strings.Contains(cmdLower, "set -x")) {
		return "Nginx", "Web server installation"
	}

	// Directory creation
	if strings.Contains(cmdLower, "mkdir") {
		return "Directories", "Directory structure"
	}

	// Cleanup commands
	if strings.Contains(cmdLower, "rm -rf") || strings.Contains(cmdLower, "apt-get clean") {
		return "Cleanup", "Removing temporary files"
	}

	// Default
	return "Other", "Build step"
}

// categorizeCopy analyzes COPY commands
func categorizeCopy(cmd string) (category, purpose string) {
	cmdLower := strings.ToLower(cmd)

	// Binary files
	if strings.Contains(cmdLower, "/api") || strings.Contains(cmdLower, "/app/api") ||
		strings.Contains(cmdLower, "/server") || strings.Contains(cmdLower, "/main") {
		return "Binary", "Compiled application binary"
	}

	// Static web files
	if strings.Contains(cmdLower, "dist") || strings.Contains(cmdLower, "build") ||
		strings.Contains(cmdLower, "public") || strings.Contains(cmdLower, "html") ||
		strings.Contains(cmdLower, "static") {
		return "Static files", "Frontend assets (JS, CSS, HTML)"
	}

	// Config files
	if strings.Contains(cmdLower, "config") || strings.Contains(cmdLower, ".json") ||
		strings.Contains(cmdLower, ".yml") || strings.Contains(cmdLower, ".yaml") ||
		strings.Contains(cmdLower, ".toml") || strings.Contains(cmdLower, ".conf") {
		return "Config", "Configuration files"
	}

	// Nginx config
	if strings.Contains(cmdLower, "nginx") {
		return "Nginx config", "Web server configuration"
	}

	// Source code
	if strings.Contains(cmdLower, "/src") || strings.Contains(cmdLower, "/app") {
		return "Source", "Application source code"
	}

	return "Files", "Copied files"
}

// extractPackages tries to extract package names from install commands
func extractPackages(cmd, manager string) string {
	// Common patterns to identify packages
	knownPackages := map[string]string{
		"nftables":        "nftables",
		"iptables":        "iptables",
		"wireguard":       "wireguard-tools",
		"iproute":         "iproute2",
		"dnsutils":        "dnsutils",
		"curl":            "curl",
		"wget":            "wget",
		"ca-certificates": "ca-certificates",
		"openssl":         "openssl",
		"git":             "git",
		"gcc":             "gcc",
		"build-essential": "build-essential",
		"nginx":           "nginx",
		"nodejs":          "nodejs",
		"python":          "python",
	}

	found := make([]string, 0)
	cmdLower := strings.ToLower(cmd)

	for key, name := range knownPackages {
		if strings.Contains(cmdLower, key) {
			found = append(found, name)
		}
	}

	if len(found) > 0 {
		if len(found) > 4 {
			return strings.Join(found[:4], ", ") + "..."
		}
		return strings.Join(found, ", ")
	}

	return ""
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// truncateCommand shortens long Docker commands for display
func truncateCommand(cmd string) string {
	// Remove common prefixes
	cmd = strings.TrimPrefix(cmd, "/bin/sh -c ")
	cmd = strings.TrimPrefix(cmd, "#(nop) ")

	if len(cmd) > 80 {
		return cmd[:77] + "..."
	}
	return cmd
}

// DockerInfo represents Docker daemon system info
type DockerInfo struct {
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containersRunning"`
	ContainersPaused  int    `json:"containersPaused"`
	ContainersStopped int    `json:"containersStopped"`
	Images            int    `json:"images"`
	ServerVersion     string `json:"serverVersion"`
	NCPU              int    `json:"ncpu"`
	MemTotal          int64  `json:"memTotal"`
	MemTotalHR        string `json:"memTotalHR"`
	StorageDriver     string `json:"storageDriver"`
	OperatingSystem   string `json:"operatingSystem"`
	OSType            string `json:"osType"`
	Architecture      string `json:"architecture"`
}

// DiskUsage represents Docker disk usage
type DiskUsage struct {
	ImagesSize       int64  `json:"imagesSize"`
	ImagesSizeHR     string `json:"imagesSizeHR"`
	ImagesCount      int    `json:"imagesCount"`
	ContainersSize   int64  `json:"containersSize"`
	ContainersSizeHR string `json:"containersSizeHR"`
	ContainersCount  int    `json:"containersCount"`
	VolumesSize      int64  `json:"volumesSize"`
	VolumesSizeHR    string `json:"volumesSizeHR"`
	VolumesCount     int    `json:"volumesCount"`
	BuildCacheSize   int64  `json:"buildCacheSize"`
	BuildCacheSizeHR string `json:"buildCacheSizeHR"`
	TotalSize        int64  `json:"totalSize"`
	TotalSizeHR      string `json:"totalSizeHR"`
}

// ContainerStats represents container resource usage
type ContainerStats struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpuPercent"`
	MemUsage   int64   `json:"memUsage"`
	MemLimit   int64   `json:"memLimit"`
	MemPercent float64 `json:"memPercent"`
	MemUsageHR string  `json:"memUsageHR"`
	MemLimitHR string  `json:"memLimitHR"`
	NetRx      int64   `json:"netRx"`
	NetTx      int64   `json:"netTx"`
	NetRxHR    string  `json:"netRxHR"`
	NetTxHR    string  `json:"netTxHR"`
	BlockRead  int64   `json:"blockRead"`
	BlockWrite int64   `json:"blockWrite"`
}

// DockerStats combines all Docker statistics
type DockerStats struct {
	Info       *DockerInfo       `json:"info,omitempty"`
	DiskUsage  *DiskUsage        `json:"diskUsage,omitempty"`
	Containers []Container       `json:"containers"`
	Stats      []ContainerStats  `json:"stats,omitempty"`
}

// GetInfo returns Docker daemon system info
func (s *Service) GetInfo() (*DockerInfo, error) {
	resp, err := s.doRequest("GET", "/v1.44/info")
	if err != nil {
		return nil, fmt.Errorf("failed to get docker info: %w", err)
	}
	defer resp.Body.Close()

	var raw struct {
		Containers        int    `json:"Containers"`
		ContainersRunning int    `json:"ContainersRunning"`
		ContainersPaused  int    `json:"ContainersPaused"`
		ContainersStopped int    `json:"ContainersStopped"`
		Images            int    `json:"Images"`
		ServerVersion     string `json:"ServerVersion"`
		NCPU              int    `json:"NCPU"`
		MemTotal          int64  `json:"MemTotal"`
		Driver            string `json:"Driver"`
		OperatingSystem   string `json:"OperatingSystem"`
		OSType            string `json:"OSType"`
		Architecture      string `json:"Architecture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse docker info: %w", err)
	}

	return &DockerInfo{
		Containers:        raw.Containers,
		ContainersRunning: raw.ContainersRunning,
		ContainersPaused:  raw.ContainersPaused,
		ContainersStopped: raw.ContainersStopped,
		Images:            raw.Images,
		ServerVersion:     raw.ServerVersion,
		NCPU:              raw.NCPU,
		MemTotal:          raw.MemTotal,
		MemTotalHR:        formatBytes(raw.MemTotal),
		StorageDriver:     raw.Driver,
		OperatingSystem:   raw.OperatingSystem,
		OSType:            raw.OSType,
		Architecture:      raw.Architecture,
	}, nil
}

// GetDiskUsage returns Docker disk usage stats
func (s *Service) GetDiskUsage() (*DiskUsage, error) {
	resp, err := s.doRequest("GET", "/v1.44/system/df")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}
	defer resp.Body.Close()

	var raw struct {
		LayersSize  int64 `json:"LayersSize"`
		Images      []struct{ Size int64 }
		Containers  []struct{ SizeRw int64 }
		Volumes     []struct{ UsageData struct{ Size int64 } }
		BuildCache  []struct{ Size int64 }
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse disk usage: %w", err)
	}

	du := &DiskUsage{
		ImagesCount:     len(raw.Images),
		ContainersCount: len(raw.Containers),
		VolumesCount:    len(raw.Volumes),
	}

	// Sum image sizes
	for _, img := range raw.Images {
		du.ImagesSize += img.Size
	}

	// Sum container sizes
	for _, c := range raw.Containers {
		du.ContainersSize += c.SizeRw
	}

	// Sum volume sizes
	for _, v := range raw.Volumes {
		du.VolumesSize += v.UsageData.Size
	}

	// Sum build cache sizes
	for _, bc := range raw.BuildCache {
		du.BuildCacheSize += bc.Size
	}

	du.TotalSize = du.ImagesSize + du.ContainersSize + du.VolumesSize + du.BuildCacheSize

	// Format human-readable sizes
	du.ImagesSizeHR = formatBytes(du.ImagesSize)
	du.ContainersSizeHR = formatBytes(du.ContainersSize)
	du.VolumesSizeHR = formatBytes(du.VolumesSize)
	du.BuildCacheSizeHR = formatBytes(du.BuildCacheSize)
	du.TotalSizeHR = formatBytes(du.TotalSize)

	return du, nil
}

// GetContainerStats returns resource usage for a specific container (non-streaming, one-shot)
func (s *Service) GetContainerStats(containerID, containerName string) (*ContainerStats, error) {
	// stream=false for one-shot stats
	resp, err := s.doRequest("GET", "/v1.44/containers/"+containerID+"/stats?stream=false")
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("container not found")
	}

	var raw struct {
		Read      string `json:"read"`
		CPUStats  struct {
			CPUUsage struct {
				TotalUsage int64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage int64 `json:"system_cpu_usage"`
			OnlineCPUs     int   `json:"online_cpus"`
		} `json:"cpu_stats"`
		PreCPUStats struct {
			CPUUsage struct {
				TotalUsage int64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage int64 `json:"system_cpu_usage"`
		} `json:"precpu_stats"`
		MemoryStats struct {
			Usage int64 `json:"usage"`
			Limit int64 `json:"limit"`
		} `json:"memory_stats"`
		Networks map[string]struct {
			RxBytes int64 `json:"rx_bytes"`
			TxBytes int64 `json:"tx_bytes"`
		} `json:"networks"`
		BlkioStats struct {
			IoServiceBytesRecursive []struct {
				Op    string `json:"op"`
				Value int64  `json:"value"`
			} `json:"io_service_bytes_recursive"`
		} `json:"blkio_stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse container stats: %w", err)
	}

	// Calculate CPU percentage
	var cpuPercent float64
	cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(raw.CPUStats.SystemCPUUsage - raw.PreCPUStats.SystemCPUUsage)
	if systemDelta > 0 && cpuDelta > 0 {
		cpuPercent = (cpuDelta / systemDelta) * float64(raw.CPUStats.OnlineCPUs) * 100.0
	}

	// Sum network IO across all interfaces
	var netRx, netTx int64
	for _, net := range raw.Networks {
		netRx += net.RxBytes
		netTx += net.TxBytes
	}

	// Sum block IO
	var blockRead, blockWrite int64
	for _, bio := range raw.BlkioStats.IoServiceBytesRecursive {
		switch bio.Op {
		case "Read":
			blockRead += bio.Value
		case "Write":
			blockWrite += bio.Value
		}
	}

	// Calculate memory percentage
	var memPercent float64
	if raw.MemoryStats.Limit > 0 {
		memPercent = float64(raw.MemoryStats.Usage) / float64(raw.MemoryStats.Limit) * 100.0
	}

	return &ContainerStats{
		ID:         containerID,
		Name:       containerName,
		CPUPercent: cpuPercent,
		MemUsage:   raw.MemoryStats.Usage,
		MemLimit:   raw.MemoryStats.Limit,
		MemPercent: memPercent,
		MemUsageHR: formatBytes(raw.MemoryStats.Usage),
		MemLimitHR: formatBytes(raw.MemoryStats.Limit),
		NetRx:      netRx,
		NetTx:      netTx,
		NetRxHR:    formatBytes(netRx),
		NetTxHR:    formatBytes(netTx),
		BlockRead:  blockRead,
		BlockWrite: blockWrite,
	}, nil
}

// GetOverviewStats returns docker info and disk usage for overview page (cached)
func (s *Service) GetOverviewStats() (*DockerInfo, *DiskUsage) {
	s.overviewMu.RLock()
	cacheValid := time.Since(s.cacheTime) < s.cacheTTL
	info := s.cachedInfo
	du := s.cachedDiskUsage
	refreshing := s.cacheRefreshing
	s.overviewMu.RUnlock()

	// Return cached values if valid
	if cacheValid && (info != nil || du != nil) {
		return info, du
	}

	// If already refreshing in background, return stale cache
	if refreshing {
		return info, du
	}

	// Refresh cache in background
	s.overviewMu.Lock()
	if s.cacheRefreshing {
		s.overviewMu.Unlock()
		return info, du
	}
	s.cacheRefreshing = true
	s.overviewMu.Unlock()

	go s.refreshOverviewCache()

	// Return whatever we have (may be nil on first call)
	return info, du
}

// refreshOverviewCache fetches fresh docker stats in background
func (s *Service) refreshOverviewCache() {
	defer func() {
		s.overviewMu.Lock()
		s.cacheRefreshing = false
		s.overviewMu.Unlock()
	}()

	var info *DockerInfo
	var du *DiskUsage

	if i, err := s.GetInfo(); err == nil {
		info = i
	}
	if d, err := s.GetDiskUsage(); err == nil {
		du = d
	}

	s.overviewMu.Lock()
	s.cachedInfo = info
	s.cachedDiskUsage = du
	s.cacheTime = time.Now()
	s.overviewMu.Unlock()
}

