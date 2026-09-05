package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DockerClientTimeout is the default timeout for Docker API requests
const DockerClientTimeout = 30 * time.Second

var (
	dockerTransportOnce sync.Once
	dockerTransport     *http.Transport
)

// dockerSharedTransport builds the Docker transport once and reuses it, so
// connections are pooled (keep-alive) instead of a fresh transport + connection
// being created — and leaked until GC — on every request. DOCKER_HOST is read
// from the environment, which doesn't change over the process lifetime.
func dockerSharedTransport() *http.Transport {
	dockerTransportOnce.Do(func() {
		dockerHost := os.Getenv("DOCKER_HOST")
		if dockerHost == "" {
			dockerHost = "unix:///var/run/docker.sock"
		}
		network, address := "unix", "/var/run/docker.sock"
		if strings.HasPrefix(dockerHost, "tcp://") {
			network, address = "tcp", strings.TrimPrefix(dockerHost, "tcp://")
		} else if p := strings.TrimPrefix(dockerHost, "unix://"); p != "" {
			address = p
		}
		dockerTransport = &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial(network, address)
			},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		}
	})
	return dockerTransport
}

// NewDockerHTTPClient creates an HTTP client configured to connect to Docker.
func NewDockerHTTPClient() *http.Client {
	return NewDockerHTTPClientWithTimeout(DockerClientTimeout)
}

// NewDockerHTTPClientWithTimeout returns a Docker HTTP client with a custom
// timeout. The client struct is cheap; the pooled transport is shared.
func NewDockerHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: dockerSharedTransport(),
		Timeout:   timeout,
	}
}

// validDockerContainer restricts container names interpolated into the Docker API
// path. It disallows "/" so a name can't traverse to other API endpoints.
var validDockerContainer = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// DockerExec runs a command in a container via Docker API
func DockerExec(container string, cmd []string) error {
	if !validDockerContainer.MatchString(container) {
		return fmt.Errorf("invalid container name: %q", container)
	}
	client := NewDockerHTTPClientWithTimeout(30 * time.Second)

	cmdJSON, _ := json.Marshal(cmd)
	execBody := fmt.Sprintf(`{"AttachStdout":true,"AttachStderr":true,"Cmd":%s}`, cmdJSON)

	resp, err := client.Post(
		fmt.Sprintf("http://localhost/containers/%s/exec", container),
		"application/json",
		strings.NewReader(execBody),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return fmt.Errorf("exec create failed: status %d", resp.StatusCode)
	}

	var execCreate struct {
		Id string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&execCreate); err != nil {
		return err
	}

	resp2, err := client.Post(
		fmt.Sprintf("http://localhost/exec/%s/start", execCreate.Id),
		"application/json",
		strings.NewReader(`{"Detach":true}`),
	)
	if err != nil {
		return err
	}
	resp2.Body.Close()

	return nil
}

// DockerLogConfig returns the log-driver config for panel-created containers so
// they get the same bounded json-file logging as the compose services (which
// use the x-logging anchor). Without this, containers the panel creates via the
// Docker API (turbotunnels, vpn-router) default to unbounded json-file logs.
// Bounds come from the same env vars compose reads, with matching defaults.
func DockerLogConfig() map[string]interface{} {
	return map[string]interface{}{
		"Type": "json-file",
		"Config": map[string]string{
			"max-size": GetEnvOptional("DOCKER_LOG_MAX_SIZE", "10m"),
			"max-file": GetEnvOptional("DOCKER_LOG_MAX_FILE", "3"),
		},
	}
}
