package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api/internal/config"
)

// limiterWith returns the rate-limit middleware at rps over an empty bucket map, and a call
// helper that sends one request from addr and returns the status.
func limiterWith(t *testing.T, rps int) func(addr string) int {
	t.Helper()
	rateLimitMu.Lock()
	rateLimitBuckets = make(map[string]*rateLimitBucket)
	rateLimitSwept = time.Time{}
	rateLimitMu.Unlock()
	rt := New(&config.Config{})
	rt.config.Middleware.RateLimit.RequestsPerSecond = rps
	h := rt.rateLimitMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	return func(addr string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		req.RemoteAddr = addr
		h.ServeHTTP(rec, req)
		return rec.Code
	}
}

// Changing address inside one IPv6 /64 doesn't get a fresh allowance.
func TestRateLimitGroupsIPv6(t *testing.T) {
	call := limiterWith(t, 1) // burst of 2
	for i := 0; i < 2; i++ {
		if c := call(fmt.Sprintf("[2001:db8:0:1::%x]:1000", i+1)); c != http.StatusOK {
			t.Fatalf("request %d: %d", i, c)
		}
	}
	if c := call("[2001:db8:0:1:ffff::9]:1000"); c != http.StatusTooManyRequests {
		t.Fatalf("a new address in the same /64 got through: %d", c)
	}
	if c := call("[2001:db8:0:2::1]:1000"); c != http.StatusOK {
		t.Fatalf("another /64 was limited: %d", c)
	}
	if n := len(rateLimitBuckets); n != 2 {
		t.Fatalf("%d buckets for two /64s", n)
	}
}

// The map never grows past its cap: a flood of new clients is refused once it's full, clients
// already counted keep working, and room comes back as buckets go idle.
func TestRateLimitCap(t *testing.T) {
	call := limiterWith(t, 100)
	if c := call("192.0.2.1:1000"); c != http.StatusOK {
		t.Fatalf("first client: %d", c)
	}
	for i := 0; len(rateLimitBuckets) < maxRateLimitBuckets; i++ {
		call(fmt.Sprintf("[2001:db8:%x:%x::1]:1000", i>>16, i&0xffff))
	}
	if c := call("[2001:db8:ffff:ffff::1]:1000"); c != http.StatusTooManyRequests {
		t.Fatalf("new client past the cap: %d", c)
	}
	if n := len(rateLimitBuckets); n != maxRateLimitBuckets {
		t.Fatalf("map grew to %d", n)
	}
	if c := call("192.0.2.1:1000"); c != http.StatusOK {
		t.Fatalf("a client already counted was refused: %d", c)
	}

	// Everyone but the first client goes idle; the next new client sweeps them away.
	rateLimitMu.Lock()
	idle := time.Now().Add(-(rateLimitBurstSeconds + 1) * time.Second)
	for key, b := range rateLimitBuckets {
		if key != "192.0.2.1" {
			b.lastUpdate = idle
		}
	}
	rateLimitSwept = time.Time{}
	rateLimitMu.Unlock()
	if c := call("[2001:db8:ffff:ffff::1]:1000"); c != http.StatusOK {
		t.Fatalf("new client after idle buckets: %d", c)
	}
	if n := len(rateLimitBuckets); n != 2 {
		t.Fatalf("%d buckets after the sweep", n)
	}
}
