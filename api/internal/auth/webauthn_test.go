package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api/internal/helper"

	"github.com/go-webauthn/webauthn/protocol"
)

// TestPasskeyRequiresUserVerification: adding a passkey and logging in with one both demand user
// verification (PIN, fingerprint or face), in the options sent to the browser and in the stored
// challenge the finish step verifies against — a touch alone is never enough.
func TestPasskeyRequiresUserVerification(t *testing.T) {
	svc := newTestService(t)
	t.Setenv("ENCRYPTION_SECRET", strings.Repeat("ab", 32)) // synthetic test key (sign-ins are sealed)
	helper.InitEncryption()
	const pw = "StrongP@ss1"
	u, err := svc.CreateUser("passkey_user", pw, RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.createSession(*u, "192.0.2.10", "test")
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://panel.example.test"

	// Registration (authed, step-up with the password).
	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkeys/register/begin",
		strings.NewReader(`{"currentPassword":"`+pw+`"}`))
	req.Header.Set("Origin", origin)
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	rec := httptest.NewRecorder()
	svc.handlePasskeyRegisterBegin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register begin: status %d: %s", rec.Code, rec.Body)
	}
	var reg protocol.CredentialCreation
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	if got := reg.Response.AuthenticatorSelection.UserVerification; got != protocol.VerificationRequired {
		t.Errorf("register options: userVerification %q, want required", got)
	}
	if sd, ok := waRegChallenges.Take(u.ID, time.Now()); !ok || sd.UserVerification != protocol.VerificationRequired {
		t.Errorf("register challenge: userVerification %q (stored %v), want required", sd.UserVerification, ok)
	}

	// Login (public).
	req = httptest.NewRequest(http.MethodPost, "/api/auth/passkeys/login/begin", nil)
	req.Header.Set("Origin", origin)
	rec = httptest.NewRecorder()
	svc.handlePasskeyLoginBegin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login begin: status %d: %s", rec.Code, rec.Body)
	}
	var login struct {
		PublicKey   protocol.PublicKeyCredentialRequestOptions `json:"publicKey"`
		ChallengeID string                                     `json:"challengeId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	if got := login.PublicKey.UserVerification; got != protocol.VerificationRequired {
		t.Errorf("login options: userVerification %q, want required", got)
	}
	if sd, ok := waOpenLogin(login.ChallengeID); !ok || sd.UserVerification != protocol.VerificationRequired {
		t.Errorf("login challenge: userVerification %q (stored %v), want required", sd.UserVerification, ok)
	}
}
