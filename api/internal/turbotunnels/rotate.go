package turbotunnels

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// Rotation abuse guards (in-memory). A per-key minimum interval throttles
// rotations; invalid-key attempts per source IP trip a temporary block.
var (
	rotMu      sync.Mutex
	lastRotate = map[string]time.Time{}   // rotateKey -> last successful trigger
	ipFails    = map[string]*failWindow{} // client IP -> failed-attempt window
)

type failWindow struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
}

// Abuse-guard tuning, all overridable via env (see the getters below).
const (
	defaultRotateFailWindow    = 300  // seconds (5 min)
	defaultRotateFailThreshold = 10   // failed attempts per window
	defaultRotateBlockDuration = 1800 // seconds (30 min)
)

// rotateMinInterval is the minimum spacing between rotations for one key,
// overridable via TURBOTUNNELS_ROTATE_MIN_INTERVAL (seconds).
func rotateMinInterval() time.Duration {
	return time.Duration(helper.GetEnvIntOptional("TURBOTUNNELS_ROTATE_MIN_INTERVAL", 10)) * time.Second
}

// rotateFailWindow is the window over which invalid-key attempts are counted,
// overridable via TURBOTUNNELS_ROTATE_FAIL_WINDOW (seconds).
func rotateFailWindow() time.Duration {
	return time.Duration(helper.GetEnvIntOptional("TURBOTUNNELS_ROTATE_FAIL_WINDOW", defaultRotateFailWindow)) * time.Second
}

// rotateFailThreshold is how many invalid-key attempts within the window trip a
// block, overridable via TURBOTUNNELS_ROTATE_FAIL_THRESHOLD.
func rotateFailThreshold() int {
	return helper.GetEnvIntOptional("TURBOTUNNELS_ROTATE_FAIL_THRESHOLD", defaultRotateFailThreshold)
}

// rotateBlockDuration is how long a tripped source IP stays blocked,
// overridable via TURBOTUNNELS_ROTATE_BLOCK_DURATION (seconds).
func rotateBlockDuration() time.Duration {
	return time.Duration(helper.GetEnvIntOptional("TURBOTUNNELS_ROTATE_BLOCK_DURATION", defaultRotateBlockDuration)) * time.Second
}

// handleRotate is the PUBLIC rotation trigger: GET/POST /api/restart/{key}. It
// validates the per-tunnel key, rate-limits, blocks abusive source IPs, then
// calls the tunnel's provider rotateUrl server-side — never exposing that URL —
// and returns the result.
func (s *Service) handleRotate(w http.ResponseWriter, r *http.Request) {
	key := router.ExtractPathParam(r, "/api/restart/")
	ip := helper.GetClientIP(r)

	if rotateBlocked(ip) {
		router.JSONError(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}

	cfg, err := LoadConfig()
	if err != nil {
		router.JSONError(w, "config error", http.StatusInternalServerError)
		return
	}

	var target *Tunnel
	for i := range cfg.Tunnels {
		t := &cfg.Tunnels[i]
		if t.RotateKey != "" && subtle.ConstantTimeCompare([]byte(t.RotateKey), []byte(key)) == 1 {
			target = t
			break
		}
	}
	if target == nil || target.RotateURL == "" {
		rotateRecordFail(ip)
		router.JSONError(w, "invalid key", http.StatusForbidden)
		return
	}

	// Per-key rate limit.
	rotMu.Lock()
	if last, ok := lastRotate[key]; ok && time.Since(last) < rotateMinInterval() {
		rotMu.Unlock()
		router.JSONError(w, "rate limited, slow down", http.StatusTooManyRequests)
		return
	}
	lastRotate[key] = time.Now()
	rotMu.Unlock()

	rotateClearFails(ip) // a valid key clears this IP's failure streak

	ok, code, body := callProviderRotate(target.RotateURL)
	providerResp := formatProviderBody(body)
	if !ok {
		router.JSONWithStatus(w, map[string]interface{}{"ok": false, "error": "provider request failed", "providerStatus": code, "providerResponse": providerResp}, http.StatusBadGateway)
		return
	}
	router.JSON(w, map[string]interface{}{"ok": true, "tunnel": target.Name, "providerStatus": code, "providerResponse": providerResp})
}

// rotateHTTPClient refuses to follow redirects, so a provider "change IP" URL
// can't bounce the server-side request onward to an internal address (SSRF). No
// IP filtering: private targets (WG 10.8.x, Headscale 100.64.x, LAN) are all
// legitimate here — the URL is admin-configured, the public caller only supplies
// the key that selects a pre-set tunnel.
var rotateHTTPClient = &http.Client{
	Timeout:       15 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// callProviderRotate GETs the provider's "change IP" endpoint server-side. It
// returns whether it succeeded, the provider's HTTP status, and a capped copy of
// the response body (surfaced back to the key holder).
func callProviderRotate(url string) (bool, int, string) {
	resp, err := rotateHTTPClient.Get(url)
	if err != nil {
		return false, 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode >= 200 && resp.StatusCode < 400, resp.StatusCode, strings.TrimSpace(string(body))
}

// formatProviderBody returns the provider body as raw JSON when it already IS
// valid JSON — so the client sees a nested object, not an escaped string — and
// as a plain string otherwise.
func formatProviderBody(body string) interface{} {
	if body != "" && json.Valid([]byte(body)) {
		return json.RawMessage(body)
	}
	return body
}

func rotateBlocked(ip string) bool {
	rotMu.Lock()
	defer rotMu.Unlock()
	fw := ipFails[ip]
	return fw != nil && time.Now().Before(fw.blockedUntil)
}

func rotateRecordFail(ip string) {
	rotMu.Lock()
	defer rotMu.Unlock()
	now := time.Now()
	fw := ipFails[ip]
	if fw == nil || now.Sub(fw.windowStart) > rotateFailWindow() {
		fw = &failWindow{windowStart: now}
		ipFails[ip] = fw
	}
	fw.count++
	if fw.count >= rotateFailThreshold() {
		fw.blockedUntil = now.Add(rotateBlockDuration())
	}
}

func rotateClearFails(ip string) {
	rotMu.Lock()
	delete(ipFails, ip)
	rotMu.Unlock()
}

// StartRotateGuardCleanup periodically evicts expired abuse-guard entries so the
// in-memory maps can't grow without bound (e.g. from many distinct — possibly
// spoofed — source IPs sending invalid keys).
func StartRotateGuardCleanup(ctx context.Context) {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now()
				rotMu.Lock()
				for ip, fw := range ipFails {
					// Drop once any block has lapsed AND the fail window is stale.
					if now.After(fw.blockedUntil) && now.Sub(fw.windowStart) > rotateFailWindow() {
						delete(ipFails, ip)
					}
				}
				for k, ts := range lastRotate {
					// Absent == "allowed", same as an expired entry.
					if now.Sub(ts) > rotateMinInterval() {
						delete(lastRotate, k)
					}
				}
				rotMu.Unlock()
			}
		}
	}()
}
