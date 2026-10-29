package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api/internal/database"
	"api/internal/helper"

	"github.com/pquerna/otp/totp"
)

// TestChangePasswordStatus: change-password is a step-up action. A wrong current password, or a
// missing or wrong 2FA code when 2FA is on, is a 428 the page shows; a refused new password is a
// 400; never a 401 (which the UI treats as "session ended" and logs out). A refused attempt
// changes nothing.
func TestChangePasswordStatus(t *testing.T) {
	svc := newTestService(t)
	t.Setenv("ENCRYPTION_SECRET", strings.Repeat("ef", 32)) // synthetic test key
	helper.InitEncryption()
	const pw = "StrongP@ss1"
	u, err := svc.CreateUser("change_pw", pw, RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { passwordLimiter.clear(u.ID); totpLimiter.clear(u.ID) })
	sess, err := svc.createSession(*u, "192.0.2.12", "test")
	if err != nil {
		t.Fatal(err)
	}
	change := func(current, code, next string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password",
			strings.NewReader(fmt.Sprintf(`{"currentPassword":%q,"totpCode":%q,"newPassword":%q}`, current, code, next)))
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		rec := httptest.NewRecorder()
		svc.handleChangePassword(rec, req)
		return rec
	}
	expect := func(name string, rec *httptest.ResponseRecorder, code int, want string) {
		t.Helper()
		if rec.Code != code || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: status %d %s, want %d mentioning %q", name, rec.Code, rec.Body, code, want)
		}
	}

	expect("wrong current password", change("wrong", "", "N3wStrongP@ss"), http.StatusPreconditionRequired, "incorrect")
	expect("same as the old one", change(pw, "", pw), http.StatusBadRequest, "different")
	expect("too weak", change(pw, "", "short"), http.StatusBadRequest, "at least")

	// With 2FA on, the password alone is not enough.
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "change_pw"})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := helper.Encrypt(key.Secret())
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE users SET totp_enabled = 1, totp_secret_enc = ? WHERE id = ?", enc, u.ID); err != nil {
		t.Fatal(err)
	}
	expect("2FA on, no code", change(pw, "", "N3wStrongP@ss"), http.StatusPreconditionRequired, "two-factor")
	expect("2FA on, wrong code", change(pw, "000000", "N3wStrongP@ss"), http.StatusPreconditionRequired, "invalid")
	if err := svc.VerifyPassword(u.ID, pw); err != nil {
		t.Fatalf("a refused change changed the password: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expect("2FA on, right code", change(pw, code, "N3wStrongP@ss"), http.StatusOK, "changed")
	if err := svc.VerifyPassword(u.ID, "N3wStrongP@ss"); err != nil {
		t.Fatalf("new password not set: %v", err)
	}
}
