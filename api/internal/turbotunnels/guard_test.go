package turbotunnels

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Guessing tunnel keys from new addresses inside one IPv6 /64 still trips the block, on both
// public doors; another /64 is unaffected.
func TestGuardGroupsIPv6(t *testing.T) {
	s := &Service{}
	for name, h := range map[string]http.HandlerFunc{"rotate": s.handleRotate, "webhook": s.handleWebhook} {
		rotMu.Lock()
		ipFails = map[string]*failWindow{}
		rotMu.Unlock()
		call := func(addr string) int {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/"+map[string]string{"rotate": "restart", "webhook": "hook"}[name]+"/wrong-key", nil)
			req.RemoteAddr = addr
			h(rec, req)
			return rec.Code
		}
		for i := 0; i < rotateFailThreshold(); i++ {
			if c := call(fmt.Sprintf("[2001:db8:0:7::%x]:1000", i+1)); c == http.StatusTooManyRequests {
				t.Fatalf("%s: blocked after %d guesses", name, i)
			}
		}
		if c := call("[2001:db8:0:7:ffff::1]:1000"); c != http.StatusTooManyRequests {
			t.Fatalf("%s: a new address in the same /64 kept guessing: %d", name, c)
		}
		if c := call("[2001:db8:0:8::1]:1000"); c == http.StatusTooManyRequests {
			t.Fatalf("%s: another /64 was blocked", name)
		}
	}
}
