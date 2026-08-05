package helper

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	trustedProxyCIDRs []*net.IPNet
	trustedProxyMutex sync.RWMutex
)

// RedactSecretPath hides secrets carried in the URL path — the rotation key in
// /api/restart/{key} and the webhook keys in /api/hook/{keys...} — so they never
// land in any log sink (the app log or the Traefik-sourced inbound logs shown on
// the Logs page). It receives only the path (query params are logged separately,
// and callers should send webhook params in the body, not the query string).
func RedactSecretPath(path string) string {
	for _, p := range []string{"/api/restart/", "/api/hook/"} {
		if strings.HasPrefix(path, p) && len(path) > len(p) {
			return p + "[redacted]"
		}
	}
	return path
}

// InitTrustedProxies initializes the list of trusted proxy CIDRs
// Pass comma-separated CIDR list, e.g. "172.18.0.0/24,10.0.0.0/8"
func InitTrustedProxies(cidrs string) {
	trustedProxyMutex.Lock()
	defer trustedProxyMutex.Unlock()

	trustedProxyCIDRs = nil
	if cidrs == "" {
		return
	}

	for _, cidrStr := range strings.Split(cidrs, ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// Accept a bare IP as a single-host CIDR (/32 or /128), so a bare-IP
			// entry isn't silently dropped.
			if ip := net.ParseIP(cidrStr); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				_, cidr, err = net.ParseCIDR(fmt.Sprintf("%s/%d", cidrStr, bits))
			}
			if err != nil {
				log.Printf("Warning: TRUSTED_PROXIES entry %q is not a valid IP or CIDR — ignored", cidrStr)
				continue
			}
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, cidr)
	}
	if len(trustedProxyCIDRs) == 0 {
		log.Printf("Warning: no valid TRUSTED_PROXIES configured — forwarding headers are ignored, so every request appears to come from the immediate peer (set TRUSTED_PROXIES to your proxy IP/CIDR, e.g. the Traefik container IP)")
	}
}

// IsTrustedProxy checks if an IP is in the trusted proxy list
func IsTrustedProxy(ipStr string) bool {
	trustedProxyMutex.RLock()
	defer trustedProxyMutex.RUnlock()

	if len(trustedProxyCIDRs) == 0 {
		// Fail closed: with no trusted proxies configured we must NOT trust any
		// forwarding header, or a direct caller could spoof its client IP.
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// GetClientIP extracts the real client IP from an HTTP request.
//
// Forwarding headers are only honoured when the immediate peer is a trusted proxy
// — a direct caller can forge them. Two cases:
//   - Behind Cloudflare: if the hop that reached our proxy is a Cloudflare edge
//     IP, then Cloudflare set CF-Connecting-IP to the real visitor and it is
//     authoritative. An attacker bypassing Cloudflare can't satisfy this (their
//     hop isn't a Cloudflare IP), so a forged CF-Connecting-IP is ignored.
//   - Otherwise: X-Forwarded-For is client-controlled on the LEFT and each proxy
//     appends on the RIGHT, so the real client is the right-most entry that isn't
//     one of our own trusted proxies. (Taking the left-most, as this used to, is
//     what let a caller spoof its IP.)
func GetClientIP(r *http.Request) string {
	remoteIP := stripPort(r.RemoteAddr)

	// Untrusted immediate peer → ignore all forwarding headers.
	if !IsTrustedProxy(remoteIP) {
		return remoteIP
	}

	xff := splitForwarded(r.Header.Get("X-Forwarded-For"))

	// Came through Cloudflare? Then CF-Connecting-IP is the real visitor.
	if len(xff) > 0 && isCloudflareIP(xff[len(xff)-1]) {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			return cf
		}
	}

	// Otherwise: right-most X-Forwarded-For entry that isn't one of our proxies.
	chain := append(xff, remoteIP)
	for i := len(chain) - 1; i >= 0; i-- {
		if ip := chain[i]; ip != "" && !IsTrustedProxy(ip) {
			return ip
		}
	}
	if len(chain) > 0 && chain[0] != "" {
		return chain[0]
	}
	return remoteIP
}

// defaultCloudflareCIDRs is the bundled fallback list of Cloudflare edge ranges,
// used at boot and whenever a live refresh fails. Source: https://www.cloudflare.com/ips/
var defaultCloudflareCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// cloudflareCIDRsStore holds the active []*net.IPNet. The updater swaps it
// atomically so isCloudflareIP reads it lock-free on the request hot path.
var cloudflareCIDRsStore atomic.Value

func init() {
	cloudflareCIDRsStore.Store(mustParseCIDRs(defaultCloudflareCIDRs))
}

func cloudflareRanges() []*net.IPNet {
	nets, _ := cloudflareCIDRsStore.Load().([]*net.IPNet)
	return nets
}

func mustParseCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, c := range list {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// isCloudflareIP reports whether ipStr is within a Cloudflare edge range.
func isCloudflareIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range cloudflareRanges() {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// StartCloudflareIPUpdater refreshes the Cloudflare edge-range list from
// Cloudflare's published endpoints on startup and every 24h. Any failure keeps
// the current list (bundled defaults at minimum) — it never fails closed.
func StartCloudflareIPUpdater(ctx context.Context) {
	go func() {
		refresh := func() {
			nets, err := fetchCloudflareCIDRs(ctx)
			if err != nil {
				log.Printf("Cloudflare IP refresh failed, keeping current list: %v", err)
				return
			}
			cloudflareCIDRsStore.Store(nets)
			log.Printf("Cloudflare IP list refreshed: %d ranges", len(nets))
		}
		refresh()
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
}

// fetchCloudflareCIDRs pulls the current v4+v6 edge ranges from Cloudflare's
// published plain-text endpoints (one CIDR per line).
func fetchCloudflareCIDRs(ctx context.Context) ([]*net.IPNet, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var out []*net.IPNet
	for _, u := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: status %d", u, resp.StatusCode)
		}
		for _, line := range strings.Split(string(body), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				if _, n, err := net.ParseCIDR(line); err == nil {
					out = append(out, n)
				}
			}
		}
	}
	// Sanity floor: Cloudflare publishes ~15 v4 + ~7 v6 ranges. Too few means a
	// bad/partial response — reject it and keep the current list.
	if len(out) < 10 {
		return nil, fmt.Errorf("only %d ranges parsed, ignoring", len(out))
	}
	return out, nil
}

// stripPort returns the host portion of a host:port address, handling IPv6
// (e.g. "[::1]:8080" -> "::1"). Returns the input unchanged if it has no port.
func stripPort(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// splitForwarded splits an X-Forwarded-For header into trimmed, non-empty IPs.
func splitForwarded(xff string) []string {
	if xff == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
