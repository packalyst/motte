package auth

import (
	"errors"
	"testing"

	"api/internal/database"
)

// TestVerifyStepUp covers the fail-closed re-auth contract: password-only when the user has no
// 2FA, and a required (never bypassable) TOTP code once 2FA is enabled.
func TestVerifyStepUp(t *testing.T) {
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	svc, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const pw = "StrongP@ss1"
	u, err := svc.CreateUser("stepup_owner", pw, RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	id := u.ID

	// No 2FA: correct password passes, wrong password fails, TOTP code is irrelevant.
	if err := svc.VerifyStepUp(id, pw, ""); err != nil {
		t.Errorf("no-2FA correct password: got %v, want nil", err)
	}
	if err := svc.VerifyStepUp(id, "wrong", ""); err == nil {
		t.Error("no-2FA wrong password: got nil, want error")
	}
	if svc.TOTPEnabled(id) {
		t.Error("TOTPEnabled should be false before enabling 2FA")
	}

	// Enable 2FA (the secret itself is not needed to prove the fail-closed gate).
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE users SET totp_enabled = 1 WHERE id = ?", id); err != nil {
		t.Fatal(err)
	}
	if !svc.TOTPEnabled(id) {
		t.Fatal("TOTPEnabled should be true after enabling 2FA")
	}

	// With 2FA on, a correct password but NO code must demand the code — not silently pass.
	if err := svc.VerifyStepUp(id, pw, ""); !errors.Is(err, ErrStepUpTOTPRequired) {
		t.Errorf("2FA, missing code: got %v, want ErrStepUpTOTPRequired", err)
	}
	// Password is still checked first: a wrong password fails as a password error, not a code prompt.
	if err := svc.VerifyStepUp(id, "wrong", "123456"); err == nil || errors.Is(err, ErrStepUpTOTPRequired) {
		t.Errorf("2FA, wrong password: got %v, want a password error", err)
	}
}
