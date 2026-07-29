package turbotunnels

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"api/internal/helper"
)

// TestResult reports the outcome of probing a tunnel end-to-end.
type TestResult struct {
	OK        bool   `json:"ok"`
	ExitIP    string `json:"exitIp,omitempty"` // this server (direct) or the upstream (chained)
	LatencyMs int64  `json:"latencyMs,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ipEchoURL is a plain-HTTP "what's my IP" endpoint. HTTP (not HTTPS) is used so
// the request travels the proxy's plain-HTTP path, where the X-TT-Test header is
// forwarded and the proxy skips logging it.
const ipEchoURL = "http://api.ipify.org"

// TestTunnel makes an authenticated request THROUGH the given tunnel to an
// IP-echo endpoint and reports whether it works plus the exit IP (this server
// for a direct tunnel, the upstream's IP for a chained one). The request carries
// the X-TT-Test header so the proxy does not log it as a real connection.
//
// The proxy is reached over the internal docker network at the container's IP,
// so this works regardless of host firewall rules.
func TestTunnel(port int, user, pass string) TestResult {
	if port < 1 || port > 65535 {
		return TestResult{Error: "invalid port"}
	}
	host := helper.GetEnvOptional("TURBOTUNNELS_CONTAINER_IP", "172.18.0.5")

	proxyURL := &url.URL{
		Scheme: "http",
		User:   url.UserPassword(user, pass),
		Host:   fmt.Sprintf("%s:%d", host, port),
	}
	client := &http.Client{
		Timeout:   8 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	req, err := http.NewRequest("GET", ipEchoURL, nil)
	if err != nil {
		return TestResult{Error: err.Error()}
	}
	req.Header.Set("X-TT-Test", "1")

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return TestResult{Error: cleanTestError(err), LatencyMs: latency}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return TestResult{Error: "proxy rejected credentials", LatencyMs: latency}
	}
	if resp.StatusCode != http.StatusOK {
		return TestResult{Error: fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode), LatencyMs: latency}
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	return TestResult{OK: true, ExitIP: strings.TrimSpace(string(body)), LatencyMs: latency}
}

// cleanTestError turns a verbose transport error into a short, useful message.
func cleanTestError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "proxy not reachable (is it running?)"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "timed out (upstream unreachable?)"
	default:
		return msg
	}
}
