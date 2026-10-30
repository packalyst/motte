package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/helper"
)

// A password guess spread over many addresses (each under the per-client limit) pauses password
// login to that account after helper.AccountLoginMaxAttempts failures, the right password
// included. Unknown names pause the same way (no hint which accounts exist), and a paused account
// costs the client nothing.
func TestAccountLoginPause(t *testing.T) {
	svc := newTestService(t)
	const pw = "StrongP@ss1"
	if _, err := svc.CreateUser("acct_limit", pw, RoleViewer); err != nil {
		t.Fatal(err)
	}
	ip := 0
	login := func(user, pass string, from string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)))
		req.RemoteAddr = from + ":40000"
		rec := httptest.NewRecorder()
		svc.handleLogin(rec, req)
		return rec.Code
	}
	// a new documentation address every 4 tries: never the per-client limit (5)
	next := func() string { ip++; return fmt.Sprintf("198.51.%d.%d", 100+ip/4/250, ip/4%250+1) }

	for _, user := range []string{"acct_limit", "no_such_user"} {
		t.Cleanup(func() { accountLimiter.clear(accountKeyOf(user)) })
		for i := 0; i < helper.AccountLoginMaxAttempts; i++ {
			if code := login(user, "wrong", next()); code != http.StatusUnauthorized {
				t.Fatalf("%s try %d: got %d, want 401", user, i+1, code)
			}
		}
		// More tries than the per-client limit, all refused by the pause, from one address
		for i := 0; i < helper.LoginMaxAttempts+1; i++ {
			if code := login(user, pw, "203.0.113.7"); code != http.StatusTooManyRequests {
				t.Fatalf("%s after %d failures: got %d, want 429", user, helper.AccountLoginMaxAttempts, code)
			}
		}
	}
	// ...cost that address nothing: once the pause ends it signs in at once.
	t.Cleanup(func() { loginLimiter.clear(helper.RateKey("203.0.113.7")) })
	accountLimiter.clear(accountKeyOf("acct_limit"))
	if code := login("acct_limit", pw, "203.0.113.7"); code != http.StatusOK {
		t.Fatalf("right password after the pause: got %d, want 200", code)
	}
	// A different case or spaces is the same account.
	if accountKeyOf(" ACCT_limit ") != accountKeyOf("acct_limit") {
		t.Fatal("the account key must follow the stored username")
	}
}
