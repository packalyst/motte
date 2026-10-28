package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api/internal/database"

	"github.com/go-webauthn/webauthn/webauthn"
)

func isTooMany(err error) bool {
	var e *tooManyAttemptsError
	return errors.As(err, &e)
}

func TestAttemptLimiter(t *testing.T) {
	l := newAttemptLimiter[string]("Test", 3)
	for i := 1; i <= 3; i++ {
		if err := l.reserve("a"); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := l.reserve("a"); !isTooMany(err) {
		t.Fatalf("attempt 4: got %v, want locked out", err)
	}
	if err := l.reserve("a"); !isTooMany(err) {
		t.Fatalf("while locked: got %v, want locked out", err)
	}
	if err := l.reserve("b"); err != nil {
		t.Fatalf("another key is unaffected: %v", err)
	}

	// refund gives a slot back; clear forgets the key.
	l.refund("b")
	if _, ok := l.m["b"]; ok {
		t.Error("refunding the only attempt should drop the key")
	}
	l.clear("a")
	if err := l.reserve("a"); err != nil {
		t.Fatalf("after clear: %v", err)
	}

	// sweep drops entries once their window or lockout has passed.
	l.sweep(time.Now().Add(loginLockoutWindow + loginLockoutTime + time.Second))
	if len(l.m) != 0 {
		t.Errorf("sweep left %d entries", len(l.m))
	}
}

// TestPasswordRecheckLockout (B5): wrong passwords at step-up, unlock and password change lock the
// user out, after which even the right password is refused without running Argon2id; other users
// are unaffected, and StepUp answers 429 rather than re-prompting.
func TestPasswordRecheckLockout(t *testing.T) {
	svc := newTestService(t)
	const pw = "StrongP@ss1"
	u, err := svc.CreateUser("pw_lockout", pw, RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	other, err := svc.CreateUser("pw_lockout_other", pw, RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { passwordLimiter.clear(u.ID); passwordLimiter.clear(other.ID) })

	// A success clears earlier failures.
	if err := svc.VerifyPassword(u.ID, "wrong"); !errors.Is(err, errPasswordIncorrect) {
		t.Fatalf("wrong password: got %v", err)
	}
	if err := svc.VerifyPassword(u.ID, pw); err != nil {
		t.Fatalf("right password: %v", err)
	}

	for i := 1; i <= maxPasswordAttempts; i++ {
		if err := svc.VerifyPassword(u.ID, "wrong"); !errors.Is(err, errPasswordIncorrect) {
			t.Fatalf("wrong password %d: got %v", i, err)
		}
	}
	if err := svc.VerifyPassword(u.ID, pw); !isTooMany(err) {
		t.Fatalf("right password while locked out: got %v, want locked out", err)
	}
	if err := svc.ChangePassword(u.ID, pw, "N3wStrongP@ss"); !isTooMany(err) {
		t.Fatalf("password change while locked out: got %v, want locked out", err)
	}
	if err := svc.VerifyPassword(other.ID, pw); err != nil {
		t.Fatalf("other user: %v", err)
	}

	rec := httptest.NewRecorder()
	if svc.StepUp(rec, u.ID, pw, "") {
		t.Fatal("StepUp passed while locked out")
	}
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("StepUp while locked out: status %d, Retry-After %q; want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// TestDisable2FAUsesStepUp: turning 2FA off goes through step-up, so a wrong password re-prompts
// (428, not a 401 that logs the user out) and 2FA marked on without a secret fails closed instead
// of being switched off without a code check.
func TestDisable2FAUsesStepUp(t *testing.T) {
	svc := newTestService(t)
	const pw = "StrongP@ss1"
	u, err := svc.CreateUser("disable_2fa", pw, RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { passwordLimiter.clear(u.ID); totpLimiter.clear(u.ID) })
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE users SET totp_enabled = 1, totp_secret_enc = NULL WHERE id = ?", u.ID); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.createSession(*u, "192.0.2.11", "test")
	if err != nil {
		t.Fatal(err)
	}
	disable := func(password string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/disable",
			strings.NewReader(fmt.Sprintf(`{"password":%q,"code":"123456"}`, password)))
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		rec := httptest.NewRecorder()
		svc.handleDisable2FA(rec, req)
		return rec
	}

	if rec := disable("wrong"); rec.Code != http.StatusPreconditionRequired {
		t.Errorf("wrong password: status %d, want 428", rec.Code)
	}
	if rec := disable(pw); rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), "misconfigured") {
		t.Errorf("missing secret: status %d %s, want 428 misconfigured", rec.Code, rec.Body)
	}
	if !svc.TOTPEnabled(u.ID) {
		t.Error("2FA was switched off without a valid code")
	}
}

// TestPasskeyLoginCap (B8): waiting passkey sign-ins are capped per IP and in total, and a slot is
// freed once a sign-in finishes.
func TestPasskeyLoginCap(t *testing.T) {
	reset := func() {
		waMu.Lock()
		waChallenges = map[string]*waChallenge{}
		waMu.Unlock()
	}
	reset()
	t.Cleanup(reset)
	var data webauthn.SessionData

	var first string
	for i := 1; i <= maxPendingPasskeyLoginsPerIP; i++ {
		id, err := waStoreLoginChallenge("192.0.2.20", data)
		if err != nil {
			t.Fatalf("sign-in %d: %v", i, err)
		}
		if first == "" {
			first = id
		}
	}
	if _, err := waStoreLoginChallenge("192.0.2.20", data); !errors.Is(err, errTooManyPasskeyLogins) {
		t.Fatalf("one over the per-IP cap: got %v", err)
	}
	if _, err := waStoreLoginChallenge("192.0.2.21", data); err != nil {
		t.Fatalf("another IP: %v", err)
	}
	if _, ok := waTakeChallenge(waLoginPrefix + first); !ok {
		t.Fatal("stored sign-in not found")
	}
	if _, err := waStoreLoginChallenge("192.0.2.20", data); err != nil {
		t.Fatalf("after one finished: %v", err)
	}

	// Total cap, from many IPs. A pending registration doesn't count toward it.
	reset()
	waStoreChallenge("reg:1", data)
	for i := 0; i < maxPendingPasskeyLogins; i++ {
		if _, err := waStoreLoginChallenge(fmt.Sprintf("10.%d.%d.1", i/250, i%250), data); err != nil {
			t.Fatalf("sign-in %d: %v", i, err)
		}
	}
	if _, err := waStoreLoginChallenge("203.0.113.1", data); !errors.Is(err, errTooManyPasskeyLogins) {
		t.Fatalf("one over the total cap: got %v", err)
	}
}

// TestFailedLoginAuditName (D11): a failed login is logged under the typed name only when that
// user exists, so a password typed into the username field never reaches the audit log.
func TestFailedLoginAuditName(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.CreateUser("audit_user", "StrongP@ss1", RoleViewer); err != nil {
		t.Fatal(err)
	}
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	for typed, want := range map[string]string{
		"Synthetic-Pasted-Passw0rd!": "(unknown user)",
		" Audit_User ":               "audit_user",
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
			strings.NewReader(fmt.Sprintf(`{"username":%q,"password":"wrong"}`, typed)))
		req.RemoteAddr = "192.0.2.30:40000"
		svc.handleLogin(httptest.NewRecorder(), req)
		var actor string
		if err := db.QueryRow(`SELECT actor FROM events WHERE type = 'login_failed' ORDER BY id DESC LIMIT 1`).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		if actor != want {
			t.Errorf("typed %q: logged as %q, want %q", typed, actor, want)
		}
	}
	loginLimiter.clear("192.0.2.30")
}
