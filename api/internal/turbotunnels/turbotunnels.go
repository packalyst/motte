// Package turbotunnels manages the optional turbotunnels forward-proxy
// container from the admin panel.
//
// The container image is built locally (build: ./turbotunnels) and cannot be
// pulled from a registry; the docker-socket-proxy also blocks image builds. So
// the panel never builds — it only creates/starts/stops/removes the container
// from the already-built image. Config (which tunnels to run, on which ports,
// with which credentials) lives encrypted in the database and is injected into
// the container as TUNNELS_JSON at create time, so changing tunnels is just a
// recreate — no rebuild.
package turbotunnels

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"api/internal/firewall"
	"api/internal/helper"
)

// ContainerName is the fixed name of the turbotunnels container.
const ContainerName = "turbotunnels"

// labelConfigHash records, on the running container, a hash of the config it
// was created from. Comparing it to the current saved config detects "you
// edited a tunnel but haven't restarted yet" drift.
const labelConfigHash = "turbotunnels.config_hash"

// mu serializes create/start/stop so concurrent clicks can't race.
var mu sync.Mutex

// Status is the lifecycle state reported to the UI.
type Status struct {
	Status      string       `json:"status"` // running, stopped, not_created, error
	ContainerUp bool         `json:"containerUp"`
	Exists      bool         `json:"exists"`
	Image       string       `json:"image"`
	LastCheck   time.Time    `json:"lastCheck"`
	Error       string       `json:"error,omitempty"`
	Tunnels     []TunnelInfo `json:"tunnels"`        // configured proxies + example commands
	Drift       bool         `json:"drift"`          // saved config differs from what's running
}

// imageName returns the locally-built image name. docker-compose tags built
// images as "<project>-<service>"; override with TURBOTUNNELS_IMAGE if the
// compose project name differs.
func imageName() string {
	return helper.GetEnvOptional("TURBOTUNNELS_IMAGE", "wireguard-admin-panel-turbotunnels")
}

// configHash returns a stable short hash of the tunnel config as the container
// sees it (the injected TUNNELS_JSON), used for drift detection.
func configHash(tunnelsJSON string) string {
	sum := sha256.Sum256([]byte(tunnelsJSON))
	return hex.EncodeToString(sum[:8])
}

// GetStatus inspects the container and reports its lifecycle state, always
// including the configured tunnels (from the encrypted store) so the UI can
// show endpoints + commands whether or not the container is running.
func GetStatus() Status {
	status := Status{Status: "not_created", Image: imageName(), LastCheck: time.Now(), Tunnels: []TunnelInfo{}}

	cfg, err := LoadConfig()
	if err != nil {
		status.Status = "error"
		status.Error = err.Error()
		return status
	}
	status.Tunnels = tunnelInfos(cfg)

	tj, _ := cfg.tunnelsJSON()
	savedHash := configHash(tj)

	resp, err := helper.DockerRequest("GET", "/containers/"+ContainerName+"/json", nil)
	if err != nil {
		status.Status = "error"
		status.Error = "Docker API error: " + err.Error()
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return status // not created yet — a normal state, not an error
	}
	if resp.StatusCode != http.StatusOK {
		status.Status = "error"
		body, _ := io.ReadAll(resp.Body)
		status.Error = fmt.Sprintf("Docker API status %d: %s", resp.StatusCode, string(body))
		return status
	}

	var info struct {
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		status.Status = "error"
		status.Error = "Failed to parse container info"
		return status
	}

	status.Exists = true
	status.ContainerUp = info.State.Running
	if info.State.Running {
		status.Status = "running"
	} else {
		status.Status = "stopped"
	}
	status.Drift = info.Config.Labels[labelConfigHash] != savedHash
	return status
}

// Start (re)creates the container from the current saved config and starts it,
// then reconciles the firewall so the tunnels' ports are allowed. It always
// recreates so a plain start can never run stale ports/config or bind to a
// vpn-network ID that no longer exists.
func Start() error {
	mu.Lock()
	defer mu.Unlock()

	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if len(cfg.Tunnels) == 0 {
		return fmt.Errorf("no tunnels configured — add a tunnel first")
	}

	if err := removeIfExists(); err != nil {
		return err
	}
	if err := createContainer(cfg); err != nil {
		return err
	}

	startResp, err := helper.DockerRequest("POST", "/containers/"+ContainerName+"/start", nil)
	if err != nil {
		return fmt.Errorf("failed to start container: %v", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusNoContent && startResp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(startResp.Body)
		return fmt.Errorf("failed to start container (status %d): %s", startResp.StatusCode, string(body))
	}

	reconcileFirewall()
	return nil
}

// removeIfExists force-removes any existing container so the next create binds
// to the current network and publishes the current ports. turbotunnels is
// stateless, so this is always safe.
func removeIfExists() error {
	resp, err := helper.DockerRequest("GET", "/containers/"+ContainerName+"/json", nil)
	if err != nil {
		return fmt.Errorf("docker API error: %v", err)
	}
	notFound := resp.StatusCode == http.StatusNotFound
	resp.Body.Close()
	if notFound {
		return nil
	}
	if rm, _ := helper.DockerRequest("DELETE", "/containers/"+ContainerName+"?force=true", nil); rm != nil {
		rm.Body.Close()
	}
	return nil
}

// createContainer creates the turbotunnels container from the locally-built
// image, publishing each tunnel's listen port on 0.0.0.0 and injecting the
// tunnel set as TUNNELS_JSON.
func createContainer(cfg Config) error {
	tunnelsJSON, err := cfg.tunnelsJSON()
	if err != nil {
		return fmt.Errorf("failed to encode tunnels: %w", err)
	}

	exposed := map[string]interface{}{}
	bindings := map[string]interface{}{}
	for _, port := range cfg.listenPorts() {
		key := portString(port)
		exposed[key] = struct{}{}
		// Bind on all interfaces (0.0.0.0). Every tunnel is auth-protected, its
		// port is allow-listed in the firewall on start, and brute-force is
		// handled by the turbotunnels jail.
		bindings[key] = []map[string]string{{"HostPort": fmt.Sprintf("%d", port)}}
	}

	config := map[string]interface{}{
		"Image":    imageName(),
		"Hostname": ContainerName,
		"Labels":   map[string]string{labelConfigHash: configHash(tunnelsJSON)},
		"Env": []string{
			"TUNNELS_JSON=" + tunnelsJSON,
		},
		"ExposedPorts": exposed,
		"HostConfig": map[string]interface{}{
			"RestartPolicy": map[string]interface{}{"Name": "unless-stopped"},
			"PortBindings":  bindings,
		},
		"NetworkingConfig": map[string]interface{}{
			"EndpointsConfig": map[string]interface{}{
				"vpn-network": map[string]interface{}{
					"IPAMConfig": map[string]interface{}{
						"IPv4Address": helper.GetEnvOptional("TURBOTUNNELS_CONTAINER_IP", "172.18.0.5"),
					},
				},
			},
		},
	}

	body, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal container config: %v", err)
	}

	createResp, err := helper.DockerRequest("POST", "/containers/create?name="+ContainerName, body)
	if err != nil {
		return fmt.Errorf("failed to create container: %v", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("image %q not found — build it once with: docker compose --profile turbotunnels build", imageName())
	}
	if createResp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("failed to create container (status %d): %s", createResp.StatusCode, string(respBody))
	}
	return nil
}

// Stop stops the container and reconciles the firewall so the now-unused ports
// stop being allowed.
func Stop() error {
	mu.Lock()
	defer mu.Unlock()

	resp, err := helper.DockerRequest("POST", "/containers/"+ContainerName+"/stop?t=10", nil)
	if err != nil {
		return fmt.Errorf("failed to stop container: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stop container (status %d): %s", resp.StatusCode, string(body))
	}

	reconcileFirewall()
	return nil
}

// Restart recreates the container with the current saved config (picking up any
// edited tunnels/ports) and starts it. Start already recreates from the current
// config, so a restart is just a start; kept as a separate verb for a clear UI
// action.
func Restart() error {
	return Start()
}

// reconcileFirewall resyncs Docker-published ports into the firewall and
// schedules a reapply, so tunnel ports are allowed on start and removed on
// stop. Safe to call before the firewall service is ready (no-op then).
func reconcileFirewall() {
	if fw := firewall.GetService(); fw != nil {
		fw.SyncAndReapply()
	}
}

// demuxDockerLog strips the 8-byte multiplexing headers Docker prepends to each
// frame of a non-TTY log stream ([stream(1),0,0,0,size(4)] + payload) and
// returns the concatenated payloads.
func demuxDockerLog(b []byte) []byte {
	var out bytes.Buffer
	for len(b) >= 8 {
		size := int(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
		if size <= 0 || size > len(b) {
			out.Write(b) // malformed/plain stream — emit the remainder as-is
			break
		}
		out.Write(b[:size])
		b = b[size:]
	}
	return out.Bytes()
}
