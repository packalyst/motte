package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"api/internal/config"
)

// limiterWith returns a call helper that sends one request from addr through a fresh rate-limit
// middleware at rps, and returns the status.
func limiterWith(rps int) func(addr string) int {
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
	call := limiterWith(1) // burst of 2
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
}

// A flood of new clients is refused once maxRateLimitClients are tracked; clients already
// tracked keep working.
func TestRateLimitCap(t *testing.T) {
	saved := maxRateLimitClients
	maxRateLimitClients = 3
	t.Cleanup(func() { maxRateLimitClients = saved })
	call := limiterWith(1)
	if c := call("192.0.2.1:1000"); c != http.StatusOK {
		t.Fatalf("first client: %d", c)
	}
	for i := 1; i < maxRateLimitClients; i++ {
		if c := call(fmt.Sprintf("[2001:db8:%x:%x::1]:1000", i>>16, i&0xffff)); c != http.StatusOK {
			t.Fatalf("client %d refused under the cap: %d", i, c)
		}
	}
	if c := call("[2001:db8:ffff:ffff::1]:1000"); c != http.StatusTooManyRequests {
		t.Fatalf("new client past the cap: %d", c)
	}
	if c := call("192.0.2.1:1000"); c != http.StatusOK {
		t.Fatalf("a client already tracked was refused: %d", c)
	}
}
