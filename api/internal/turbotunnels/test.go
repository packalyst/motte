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

// ipEchoURL is a "what's my IP" endpoint reached over HTTPS, so the request
// travels the proxy via CONNECT — exactly like `curl -x`, whose auth is known
// to work. The X-TT-Test header is sent on the CONNECT itself (see
// ProxyConnectHeader below) so the proxy skips logging the probe.
const ipEchoURL = "https://api.ipify.org"

// TestTunnel makes an authenticated request THROUGH the given tunnel to an
// IP-echo endpoint and reports whether it works plus the exit IP (this server
// for a direct tunnel, the upstream's IP for a chained one).
//
// HTTP mirrors `curl -x http://…`: an HTTPS target used via CONNECT with the
// creds in the proxy URL (Go attaches Proxy-Authorization automatically) and an
// X-TT-Test header on the CONNECT so the proxy skips logging it. SOCKS5 uses
// Go's native socks5 proxy support (auth from the URL); the probe is kept out
// of the logs by the internal-source filter in the log streamer. The proxy is
// reached over the internal docker network at the container's IP.
func TestTunnel(protocol string, port int, user, pass string) TestResult {
	if port < 1 || port > 65535 {
		return TestResult{Error: "invalid port"}
	}
	host := helper.GetEnvOptional("TURBOTUNNELS_CONTAINER_IP", "172.18.0.5")

	socks := protocol == "socks5"
	scheme := "http"
	if socks {
		scheme = "socks5"
	}
	proxyURL := &url.URL{
		Scheme: scheme,
		User:   url.UserPassword(user, pass),
		Host:   fmt.Sprintf("%s:%d", host, port),
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	if !socks {
		// Marks the CONNECT as a health probe so the proxy skips logging it.
		transport.ProxyConnectHeader = http.Header{"X-Tt-Test": []string{"1"}}
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}

	req, err := http.NewRequest("GET", ipEchoURL, nil)
	if err != nil {
		return TestResult{Error: err.Error()}
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return TestResult{Error: cleanTestError(err), LatencyMs: latency}
	}
	defer resp.Body.Close()

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
	case strings.Contains(msg, "Proxy Authentication") || strings.Contains(msg, "407") ||
		strings.Contains(msg, "authentication failed") || strings.Contains(msg, "username/password"):
		return "proxy rejected credentials"
	case strings.Contains(msg, "connection refused"):
		return "proxy not reachable (is it running?)"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "timed out (upstream unreachable?)"
	default:
		return msg
	}
}
