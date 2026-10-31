package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"api/internal/bounded"
	"api/internal/database"
	"api/internal/helper"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
)

func isTooMany(err error) bool {
	var e *tooManyAttemptsError
	return errors.As(err, &e)
}

// The lockout itself is tested in package bounded; this checks auth's wrapper: a locked-out key
// gets a *tooManyAttemptsError naming what was locked, refund and clear reach the lockout.
func TestAttemptLimiter(t *testing.T) {
	l := newAttemptLimiter[string]("Test", 3)
	for i := 1; i <= 3; i++ {
		if err := l.reserve("a"); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	err := l.reserve("a")
	if !isTooMany(err) || !strings.Contains(err.Error(), "too many failed test attempts") {
		t.Fatalf("attempt 4: got %v, want locked out", err)
	}
	if err := l.reserve("b"); err != nil {
		t.Fatalf("another key is unaffected: %v", err)
	}
	l.clear("a")
	if err := l.reserve("a"); err != nil {
		t.Fatalf("after clear: %v", err)
	}
	for i := 0; i < 2; i++ {
		l.reserve("c")
	}
	l.refund("c")
	for i := 0; i < 2; i++ {
		if err := l.reserve("c"); err != nil {
			t.Fatalf("after a refund, attempt %d: %v", i+1, err)
		}
	}
	if err := l.reserve("c"); !isTooMany(err) {
		t.Fatalf("refund gave back more than one attempt: %v", err)
	}
}

// TestPasswordRecheckLockout (B5): wrong passwords at step-up, unlock and password change lock the
// user out, after which even the right password is refused without running Argon2id; other users
// are unaffected, and the step-up answers 429 rather than re-prompting.
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

	for i := 1; i <= helper.PasswordMaxAttempts; i++ {
		if err := svc.VerifyPassword(u.ID, "wrong"); !errors.Is(err, errPasswordIncorrect) {
			t.Fatalf("wrong password %d: got %v", i, err)
		}
	}
	if err := svc.VerifyPassword(u.ID, pw); !isTooMany(err) {
		t.Fatalf("right password while locked out: got %v, want locked out", err)
	}
	if err := svc.verifyStepUp(u.ID, pw, ""); !isTooMany(err) { // what change-password checks
		t.Fatalf("password change while locked out: got %v, want locked out", err)
	}
	if err := svc.VerifyPassword(other.ID, pw); err != nil {
		t.Fatalf("other user: %v", err)
	}

	rec := httptest.NewRecorder()
	if svc.RequireStepUp(rec, httptest.NewRequest(http.MethodPost, "/api/x", nil), u.ID, StepUpCreds{CurrentPassword: pw}) {
		t.Fatal("the step-up passed while locked out")
	}
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("step-up while locked out: status %d, Retry-After %q; want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
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

// A passkey sign-in keeps no state until it succeeds: its challenge travels sealed in the
// challengeId. A forged, altered, expired or foreign sealed value doesn't open; a verified sign-in
// can be claimed once, so its answer can't be replayed.
func TestPasskeySignInSealed(t *testing.T) {
	newTestService(t)
	t.Setenv("ENCRYPTION_SECRET", strings.Repeat("ab", 32)) // synthetic test key
	helper.InitEncryption()
	saved := waUsedLogins
	waUsedLogins = bounded.New[string, struct{}](10, bounded.Refuse)
	t.Cleanup(func() { waUsedLogins = saved })

	data := webauthn.SessionData{Challenge: "synthetic-challenge", UserVerification: "required"}
	id, err := waSealLogin(data)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := waOpenLogin(id)
	if !ok || got.Challenge != data.Challenge || got.UserVerification != "required" {
		t.Fatalf("sealed sign-in didn't open: %+v %v", got, ok)
	}
	if time.Until(got.Expires) <= 0 || time.Until(got.Expires) > helper.PasskeyChallengeTTL {
		t.Fatalf("expiry %v, want within %v", got.Expires, helper.PasskeyChallengeTTL)
	}

	// Sealed with the same key and otherwise valid (future expiry), but not marked as a sign-in.
	otherJSON, _ := json.Marshal(webauthn.SessionData{Challenge: "x", Expires: time.Now().Add(time.Minute)})
	other, _ := helper.Encrypt(string(otherJSON))
	stale := data
	stale.Expires = time.Now().Add(-time.Minute)
	b, _ := json.Marshal(stale)
	expired, _ := helper.Encrypt(waLoginSeal + string(b))
	altered := []byte(id)
	altered[len(altered)/2] ^= 1
	for name, bad := range map[string]string{"forged": "not-a-sealed-value", "altered": string(altered),
		"another kind": other, "expired": expired, "empty": ""} {
		if _, ok := waOpenLogin(bad); ok {
			t.Errorf("%s challengeId opened", name)
		}
	}

	if !waClaimLogin(got) {
		t.Fatal("a fresh sign-in couldn't be claimed")
	}
	if waClaimLogin(got) {
		t.Fatal("the same sign-in was claimed twice (replay)")
	}
	waUsedLogins = bounded.New[string, struct{}](1, bounded.Refuse)
	waClaimLogin(webauthn.SessionData{Challenge: "fills-it", Expires: time.Now().Add(time.Minute)})
	if waClaimLogin(webauthn.SessionData{Challenge: "another", Expires: time.Now().Add(time.Minute)}) {
		t.Fatal("a sign-in that couldn't be recorded was accepted")
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

// Wrong passwords from new addresses inside one IPv6 /64 still lock it out; another /64 can still
// try, and the audit log keeps the address that actually sent each attempt.
func TestLoginLockoutGroupsIPv6(t *testing.T) {
	svc := newTestService(t)
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	login := func(addr string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"nobody","password":"wrong"}`))
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		svc.handleLogin(rec, req)
		return rec.Code
	}
	t.Cleanup(func() {
		loginLimiter.clear("2001:db8:0:9::/64")
		loginLimiter.clear("2001:db8:0:a::/64")
	})
	for i := 1; i <= helper.LoginMaxAttempts; i++ {
		if c := login(fmt.Sprintf("[2001:db8:0:9::%x]:40000", i)); c != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	var ip string
	if err := db.QueryRow(`SELECT ip FROM events WHERE type = 'login_failed' ORDER BY id DESC LIMIT 1`).Scan(&ip); err != nil || ip != fmt.Sprintf("2001:db8:0:9::%x", helper.LoginMaxAttempts) {
		t.Fatalf("audit logged %q (%v), want the sending address", ip, err)
	}
	if c := login("[2001:db8:0:9:ffff::1]:40000"); c != http.StatusTooManyRequests {
		t.Fatalf("a new address in the same /64 kept guessing: %d", c)
	}
	if c := login("[2001:db8:0:a::1]:40000"); c != http.StatusUnauthorized {
		t.Fatalf("another /64 was locked out: %d", c)
	}
}

// A 2FA code works once, also after a newer one was used; and when the replay guard can't record
// it (its map is full) the code is refused rather than left replayable.
func TestTOTPSingleUse(t *testing.T) {
	newTestService(t)
	t.Setenv("ENCRYPTION_SECRET", strings.Repeat("cd", 32)) // synthetic test key
	helper.InitEncryption()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "replay"})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := helper.Encrypt(key.Secret())
	if err != nil {
		t.Fatal(err)
	}
	secret := sql.NullString{String: enc, Valid: true}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	saved := usedTOTP
	t.Cleanup(func() { usedTOTP = saved; totpLimiter.clear(9001); totpLimiter.clear(9002) })

	usedTOTP = bounded.New[usedTOTPCode, struct{}](10, bounded.Refuse)
	if err := verifyTOTP(9001, secret, code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := verifyTOTP(9001, secret, code); err == nil {
		t.Fatal("the same code was accepted twice")
	}
	// A newer code doesn't make an older one usable again (both are inside their window).
	next, err := totp.GenerateCode(key.Secret(), time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if next != code {
		if err := verifyTOTP(9001, secret, next); err != nil {
			t.Fatalf("newer code: %v", err)
		}
		if err := verifyTOTP(9001, secret, code); err == nil {
			t.Fatal("an older code was accepted again after a newer one")
		}
	}

	// Sent at the same moment, one code still passes only once.
	var wg sync.WaitGroup
	var passed atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimTOTPCode(9003, "123456") == nil {
				passed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := passed.Load(); n != 1 {
		t.Fatalf("one code passed %d times concurrently", n)
	}

	usedTOTP = bounded.New[usedTOTPCode, struct{}](1, bounded.Refuse)
	_ = claimTOTPCode(1, "000000")
	if err := verifyTOTP(9002, secret, code); err == nil {
		t.Fatal("a code the replay guard couldn't record was accepted")
	}
}
