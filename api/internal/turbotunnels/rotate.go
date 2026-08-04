package turbotunnels

import (
	"crypto/subtle"
	"io"
	"net/http"
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

const (
	rotateFailWindow    = 5 * time.Minute
	rotateFailThreshold = 10
	rotateBlockDuration = 30 * time.Minute
)

// rotateMinInterval is the minimum spacing between rotations for one key,
// overridable via TURBOTUNNELS_ROTATE_MIN_INTERVAL (seconds).
func rotateMinInterval() time.Duration {
	return time.Duration(helper.GetEnvIntOptional("TURBOTUNNELS_ROTATE_MIN_INTERVAL", 10)) * time.Second
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

	ok, code := callProviderRotate(target.RotateURL)
	if !ok {
		router.JSONWithStatus(w, map[string]interface{}{"ok": false, "error": "provider request failed", "providerStatus": code}, http.StatusBadGateway)
		return
	}
	router.JSON(w, map[string]interface{}{"ok": true, "tunnel": target.Name, "providerStatus": code})
}

// callProviderRotate GETs the provider's "change IP" endpoint server-side.
// Returns whether it succeeded and the provider's HTTP status.
func callProviderRotate(url string) (bool, int) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode >= 200 && resp.StatusCode < 400, resp.StatusCode
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
	if fw == nil || now.Sub(fw.windowStart) > rotateFailWindow {
		fw = &failWindow{windowStart: now}
		ipFails[ip] = fw
	}
	fw.count++
	if fw.count >= rotateFailThreshold {
		fw.blockedUntil = now.Add(rotateBlockDuration)
	}
}

func rotateClearFails(ip string) {
	rotMu.Lock()
	delete(ipFails, ip)
	rotMu.Unlock()
}
