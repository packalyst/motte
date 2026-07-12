// Package turbotunnels manages the optional turbotunnels forward-proxy
// container from the admin panel, mirroring the VPN router lifecycle pattern.
//
// The container image is built locally by docker-compose (build: ./turbotunnels)
// and cannot be pulled from a registry. The docker-socket-proxy also blocks
// image builds. So the lifecycle here is:
//   - Start:   start the existing container; if it does not exist yet, create it
//              from the locally-built image and start it.
//   - Stop:    stop the container.
//   - Restart: restart the container.
// If the image has never been built, Start returns an actionable error telling
// the user to build it once via docker compose.
package turbotunnels

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"api/internal/helper"
)

// ContainerName is the fixed name of the turbotunnels container (matches
// container_name in docker-compose.yml).
const ContainerName = "turbotunnels"

// mu serializes create/start/stop so concurrent clicks can't race.
var mu sync.Mutex

// Status is the lifecycle state reported to the UI.
type Status struct {
	Status      string    `json:"status"` // running, stopped, not_created, error
	ContainerUp bool      `json:"containerUp"`
	Exists      bool      `json:"exists"`
	Image       string    `json:"image"`
	LastCheck   time.Time `json:"lastCheck"`
	Error       string    `json:"error,omitempty"`
}

// imageName returns the locally-built image name. docker-compose tags built
// images as "<project>-<service>"; the project defaults to the compose
// directory name. Override with TURBOTUNNELS_IMAGE if your project name differs.
func imageName() string {
	return helper.GetEnvOptional("TURBOTUNNELS_IMAGE", "wireguard-admin-panel-turbotunnels")
}

// GetStatus inspects the container and reports its lifecycle state.
func GetStatus() Status {
	status := Status{Status: "not_created", Image: imageName(), LastCheck: time.Now()}

	resp, err := helper.DockerRequest("GET", "/containers/"+ContainerName+"/json", nil)
	if err != nil {
		status.Status = "error"
		status.Error = "Docker API error: " + err.Error()
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Container not created yet — that's a normal state, not an error.
		return status
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
	return status
}

// Start starts the container, creating it from the local image if needed.
func Start() error {
	mu.Lock()
	defer mu.Unlock()

	// If the container already exists, just start it.
	resp, err := helper.DockerRequest("GET", "/containers/"+ContainerName+"/json", nil)
	if err != nil {
		return fmt.Errorf("docker API error: %v", err)
	}
	exists := resp.StatusCode == http.StatusOK
	resp.Body.Close()

	if !exists {
		if err := createContainer(); err != nil {
			return err
		}
	}

	startResp, err := helper.DockerRequest("POST", "/containers/"+ContainerName+"/start", nil)
	if err != nil {
		return fmt.Errorf("failed to start container: %v", err)
	}
	defer startResp.Body.Close()

	// 204 = started, 304 = already running.
	if startResp.StatusCode != http.StatusNoContent && startResp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(startResp.Body)
		return fmt.Errorf("failed to start container (status %d): %s", startResp.StatusCode, string(body))
	}
	return nil
}

// createContainer creates the turbotunnels container from the locally-built
// image, mirroring the docker-compose service definition.
func createContainer() error {
	config := map[string]interface{}{
		"Image":    imageName(),
		"Hostname": ContainerName,
		"Env": []string{
			"HOST_IP=" + helper.GetEnvOptional("TURBOTUNNELS_HOST_IP", "0.0.0.0"),
			"TUNNELS_JSON=" + helper.GetEnvOptional("TUNNELS_JSON", ""),
			"TUNNELS_YAML=" + helper.GetEnvOptional("TUNNELS_YAML", "/app/tunnels.yaml"),
			"TUNNELS_ADMIN_USER=" + helper.GetEnvOptional("TUNNELS_ADMIN_USER", "admin"),
			"TUNNELS_ADMIN_PASS=" + helper.GetEnvOptional("TUNNELS_ADMIN_PASS", "changeme"),
		},
		"ExposedPorts": map[string]interface{}{
			"3128/tcp": struct{}{},
			"1080/tcp": struct{}{},
			"5000/tcp": struct{}{},
		},
		"HostConfig": map[string]interface{}{
			"RestartPolicy": map[string]interface{}{"Name": "unless-stopped"},
			"PortBindings": map[string]interface{}{
				"3128/tcp": []map[string]string{{"HostPort": "3128"}},
				"1080/tcp": []map[string]string{{"HostPort": "1080"}},
				"5000/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "5000"}},
			},
		},
		"NetworkingConfig": map[string]interface{}{
			"EndpointsConfig": map[string]interface{}{
				"vpn-network": map[string]interface{}{},
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
		// Image doesn't exist locally — it must be built first.
		return fmt.Errorf("image %q not found — build it once with: docker compose --profile turbotunnels build", imageName())
	}
	if createResp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("failed to create container (status %d): %s", createResp.StatusCode, string(respBody))
	}
	return nil
}

// Stop stops the container.
func Stop() error {
	mu.Lock()
	defer mu.Unlock()

	resp, err := helper.DockerRequest("POST", "/containers/"+ContainerName+"/stop?t=10", nil)
	if err != nil {
		return fmt.Errorf("failed to stop container: %v", err)
	}
	defer resp.Body.Close()

	// 204 = stopped, 304 = already stopped.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stop container (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// Restart restarts the container.
func Restart() error {
	mu.Lock()
	defer mu.Unlock()

	resp, err := helper.DockerRequest("POST", "/containers/"+ContainerName+"/restart?t=10", nil)
	if err != nil {
		return fmt.Errorf("failed to restart container: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to restart container (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}
