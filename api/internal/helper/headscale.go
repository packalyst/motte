package helper

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HeadscaleConfig holds the Headscale API configuration
type HeadscaleConfig struct {
	URL    string
	APIKey string
}

// Default timeouts
const (
	HeadscaleRequestTimeout = 30 * time.Second
)

// headscaleClient is a shared HTTP client for Headscale API requests
var headscaleClient = &http.Client{
	Timeout: HeadscaleRequestTimeout,
}

// HeadscaleConfigProvider is a function that returns the current Headscale config
type HeadscaleConfigProvider func() (*HeadscaleConfig, error)

// headscaleConfigProvider is the callback for getting config
var headscaleConfigProvider HeadscaleConfigProvider

// SetHeadscaleConfigProvider sets the callback for getting Headscale config
// This should be called during initialization by the settings package
func SetHeadscaleConfigProvider(provider HeadscaleConfigProvider) {
	headscaleConfigProvider = provider
}

// getHeadscaleConfig returns the config using the provider
func getHeadscaleConfig() (*HeadscaleConfig, error) {
	if headscaleConfigProvider == nil {
		return nil, fmt.Errorf("headscale config provider not set")
	}
	return headscaleConfigProvider()
}

// NormalizeHeadscaleURL ensures the URL ends with /api/v1
func NormalizeHeadscaleURL(url string) string {
	url = strings.TrimSuffix(url, "/")
	if !strings.HasSuffix(url, "/api/v1") {
		url = url + "/api/v1"
	}
	return url
}

// HeadscaleRequest makes an authenticated request to the Headscale API
func HeadscaleRequest(method, path string, body io.Reader) (*http.Response, error) {
	config, err := getHeadscaleConfig()
	if err != nil {
		return nil, err
	}

	return HeadscaleRequestWithConfig(config, method, path, body)
}

// HeadscaleRequestWithConfig makes an authenticated request using provided config
func HeadscaleRequestWithConfig(config *HeadscaleConfig, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, config.URL+path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.APIKey)

	return headscaleClient.Do(req)
}

// HeadscaleGet performs a GET request to Headscale API
func HeadscaleGet(path string) (*http.Response, error) {
	return HeadscaleRequest("GET", path, nil)
}

// HeadscalePost performs a POST request to Headscale API
func HeadscalePost(path string, body string) (*http.Response, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	return HeadscaleRequest("POST", path, reader)
}

// HeadscaleDelete performs a DELETE request to Headscale API
func HeadscaleDelete(path string) (*http.Response, error) {
	return HeadscaleRequest("DELETE", path, nil)
}

// HeadscaleGetJSON performs a GET request and decodes the JSON response
func HeadscaleGetJSON(path string, result interface{}) error {
	resp, err := HeadscaleGet(path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("headscale API error (status %d): %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(result)
}

// Docker client helpers

// DockerConfig holds Docker API configuration
type DockerConfig struct {
	APIVersion string
}

// Default Docker configuration
var DefaultDockerConfig = DockerConfig{
	APIVersion: GetEnvOptional("DOCKER_API_VERSION", "v1.44"),
}

// getDockerClient returns the shared Docker HTTP client (uses DOCKER_HOST env var)
func getDockerClient() *http.Client {
	return NewDockerHTTPClientWithTimeout(60 * time.Second)
}

// DockerRequest makes a request to the Docker API
func DockerRequest(method, path string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}

	url := fmt.Sprintf("http://docker/%s%s", DefaultDockerConfig.APIVersion, path)
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return getDockerClient().Do(req)
}

// DockerGet performs a GET request to Docker API
func DockerGet(path string) (*http.Response, error) {
	return DockerRequest("GET", path, nil)
}

// DockerPost performs a POST request to Docker API
func DockerPost(path string, body []byte) (*http.Response, error) {
	return DockerRequest("POST", path, body)
}

// DockerDelete performs a DELETE request to Docker API
func DockerDelete(path string) (*http.Response, error) {
	return DockerRequest("DELETE", path, nil)
}
