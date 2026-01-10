package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// DockerClientTimeout is the default timeout for Docker API requests
const DockerClientTimeout = 30 * time.Second

// NewDockerHTTPClient creates an HTTP client configured to connect to Docker
// It reads DOCKER_HOST env var and supports both TCP and Unix socket connections
func NewDockerHTTPClient() *http.Client {
	return NewDockerHTTPClientWithTimeout(DockerClientTimeout)
}

// NewDockerHTTPClientWithTimeout creates a Docker HTTP client with custom timeout
func NewDockerHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	var transport *http.Transport

	if strings.HasPrefix(dockerHost, "tcp://") {
		// TCP connection to docker socket proxy
		tcpAddr := strings.TrimPrefix(dockerHost, "tcp://")
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", tcpAddr)
			},
		}
	} else {
		// Unix socket (default)
		socketPath := strings.TrimPrefix(dockerHost, "unix://")
		if socketPath == "" {
			socketPath = "/var/run/docker.sock"
		}
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// DockerExec runs a command in a container via Docker API
func DockerExec(container string, cmd []string) error {
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
