package fleet

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Creating an enrollment token, and switching the agent listener off or moving it, take a step-up:
// without one nothing is created or changed.
func TestTokenAndListenerNeedStepUp(t *testing.T) {
	svc := newTestService(t)
	post := func(h http.HandlerFunc, path, body string) int {
		rr := httptest.NewRecorder()
		h(rr, asOwner(httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))))
		return rr.Code
	}
	tokens := func() (n int) { svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_tokens`).Scan(&n); return }

	if code := post(svc.handleCreateToken, "/api/fleet/token", `{"label":"laptop"}`); code != http.StatusPreconditionRequired || tokens() != 0 {
		t.Fatalf("token without step-up: %d, %d tokens", code, tokens())
	}

	// A running listener (never started here: only its state is read) on 7001.
	svc.mu.Lock()
	svc.srv, svc.port = &http.Server{}, 7001
	svc.mu.Unlock()
	for _, body := range []string{`{"enabled":false,"port":7001}`, `{"enabled":true,"port":7002}`} {
		if code := post(svc.handleSetConfig, "/api/fleet/config", body); code != http.StatusPreconditionRequired {
			t.Fatalf("%s without step-up: %d, want 428", body, code)
		}
		if on, port := svc.Status(); !on || port != 7001 {
			t.Fatalf("%s changed the listener without step-up: %v %d", body, on, port)
		}
	}
}
