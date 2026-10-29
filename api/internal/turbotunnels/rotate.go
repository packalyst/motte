package turbotunnels

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"api/internal/bounded"
	"api/internal/helper"
	"api/internal/router"
)

// Abuse-guard tuning, all overridable via env (see the getters below).
const (
	defaultRotateFailWindow    = 300  // seconds (5 min)
	defaultRotateFailThreshold = 10   // failed attempts per window
	defaultRotateBlockDuration = 1800 // seconds (30 min)

	maxGuardedClients = 100_000 // clients the key guard tracks at once; new ones are refused past it
	maxThrottledKeys  = 10_000  // tunnel and webhook keys throttled at once (only valid keys get here)
)

// The public key endpoints' abuse guards (in-memory, bounded). keyGuard locks out a client (an
// IPv6 one by its /64) after rotateFailThreshold() invalid keys within rotateFailWindow(), for
// rotateBlockDuration(); a flood of new clients can't push out a block. The throttles space out
// the firings of one rotate key or webhook.
var (
	keyGuard        = bounded.NewLockout[string](maxGuardedClients, rotateFailThreshold(), rotateFailWindow(), rotateBlockDuration())
	rotateThrottle  = bounded.New[string, time.Time](maxThrottledKeys, bounded.DropOldest) // rotate key → next allowed
	webhookThrottle = bounded.New[string, time.Time](maxThrottledKeys, bounded.DropOldest) // webhook id → next allowed
)

// guardedClient is the key guard's key for the caller, or "" after answering 429 because it is
// locked out. The attempt is reserved: a valid key must keyGuard.Clear it, a request that failed
// for another reason keyGuard.Refund it.
func guardedClient(w http.ResponseWriter, r *http.Request) string {
	client := helper.RateKey(helper.GetClientIP(r))
	if retry, _ := keyGuard.Reserve(client, time.Now()); retry > 0 {
		router.JSONError(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return ""
	}
	return client
}

// throttled reports whether key fired less than interval ago; if not, it starts a new interval.
func throttled(m *bounded.Map[string, time.Time], key string, interval time.Duration) bool {
	now := time.Now()
	blocked := false
	m.Update(key, now, func(next *time.Time, found bool) time.Time {
		if found {
			blocked = true
			return *next
		}
		*next = now.Add(interval)
		return *next
	})
	return blocked
}

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
	client := guardedClient(w, r)
	if client == "" {
		return
	}

	cfg, err := LoadConfig()
	if err != nil {
		keyGuard.Refund(client, time.Now())
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
		router.JSONError(w, "invalid key", http.StatusForbidden) // the reserved attempt stays counted
		return
	}
	keyGuard.Clear(client) // a valid key clears this client's failure streak

	// Per-key rate limit.
	if throttled(rotateThrottle, key, rotateMinInterval()) {
		router.JSONError(w, "rate limited, slow down", http.StatusTooManyRequests)
		return
	}

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
// rotateHTTPClient blocks link-local/cloud-metadata at dial time (RFC1918/LAN provider
// targets stay allowed — the URL is admin-configured) and refuses redirects, so a rotate-key
// holder can't exfil instance metadata through the capped response body returned to them.
var rotateHTTPClient = func() *http.Client {
	c := helper.SafeInternalHTTPClient(15 * time.Second)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}()

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
