package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/helper"
	"api/internal/router"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

const testOrigin = "https://panel.example.test"

// fakePasskey is a software authenticator: a P-256 key registered as one user's passkey, answering
// challenges the way a phone does (user verified unless told otherwise).
type fakePasskey struct {
	key    *ecdsa.PrivateKey
	id     []byte
	handle []byte
	count  uint32
}

func newFakePasskey(t *testing.T, svc *Service, userID int64, name string) *fakePasskey {
	t.Helper()
	svc.ensureWebAuthnTables()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         1, // P-256
		XCoord:        key.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord:        key.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	cred := webauthn.Credential{ID: id, PublicKey: pub, AttestationType: "none"}
	if err := svc.saveCredential(userID, name, "panel.example.test", &cred); err != nil {
		t.Fatal(err)
	}
	handle, err := svc.webauthnHandle(userID)
	if err != nil {
		t.Fatal(err)
	}
	return &fakePasskey{key: key, id: id, handle: handle}
}

// answer signs a challenge (base64url, as the begin response carries it); verified sets the UV flag.
func (p *fakePasskey) answer(t *testing.T, challenge string, verified bool) json.RawMessage {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	client, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": challenge, "origin": testOrigin})
	rp := sha256.Sum256([]byte("panel.example.test"))
	flags := byte(0x01) // user present
	if verified {
		flags |= 0x04 // user verified
	}
	p.count++
	auth := append(append(rp[:], flags), binary.BigEndian.AppendUint32(nil, p.count)...)
	cd := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cd[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64(p.id), "rawId": b64(p.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON": b64(client), "authenticatorData": b64(auth),
			"signature": b64(sig), "userHandle": b64(p.handle),
		},
	})
	return out
}

// A sensitive request can be confirmed with a passkey instead of the password: only with an answer
// from the caller's own passkey, with the user verified, to a challenge made for that same session
// and that same request, once.
func TestPasskeyStepUp(t *testing.T) {
	svc := newTestService(t)
	t.Setenv("ENCRYPTION_SECRET", strings.Repeat("cd", 32)) // synthetic test key
	helper.InitEncryption()
	const pw = "StrongP@ss1"
	alice, err := svc.CreateUser("stepup_passkey_alice", pw, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := svc.CreateUser("stepup_passkey_bob", pw, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	session := func(u *User) string {
		s, err := svc.createSession(*u, "192.0.2.20", "test")
		if err != nil {
			t.Fatal(err)
		}
		return s.Token
	}
	aliceTok, aliceTok2, bobTok := session(alice), session(alice), session(bob)
	aliceKey := newFakePasskey(t, svc, alice.ID, "alice phone")
	bobKey := newFakePasskey(t, svc, bob.ID, "bob phone")

	req := func(method, url, token, body string, uid int64) *http.Request {
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("Authorization", "Bearer "+token)
		return r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{UserID: uid}))
	}
	begin := func(token string, uid int64, method, url string) (int, string) {
		rec := httptest.NewRecorder()
		svc.handlePasskeyStepUpBegin(rec, req(http.MethodPost, "/api/auth/stepup/passkey", token,
			`{"method":"`+method+`","url":"`+url+`"}`, uid))
		var out struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.PublicKey.Challenge
	}
	const action = "/api/dhcp/clients/5/vpn"
	verify := func(token string, uid int64, method, url string, answer json.RawMessage) error {
		return svc.VerifyStepUpRequest(req(method, url, token, "", uid), uid, StepUpCreds{Passkey: answer})
	}

	// The happy path, and the same answer can't be used twice.
	_, ch := begin(aliceTok, alice.ID, "PUT", action)
	ans := aliceKey.answer(t, ch, true)
	if err := verify(aliceTok, alice.ID, "PUT", action, ans); err != nil {
		t.Fatalf("a valid passkey answer: %v", err)
	}
	if err := verify(aliceTok, alice.ID, "PUT", action, ans); err == nil {
		t.Fatal("a passkey answer must work once")
	}

	for _, c := range []struct {
		name          string
		token         string
		uid           int64
		method, url   string
		key           *fakePasskey
		userVerified  bool
		beginUsingTok string
	}{
		{"another request", aliceTok, alice.ID, "DELETE", "/api/auth/users/9", aliceKey, true, aliceTok},
		{"another query", aliceTok, alice.ID, "PUT", action + "?x=1", aliceKey, true, aliceTok},
		{"another session of the same user", aliceTok2, alice.ID, "PUT", action, aliceKey, true, aliceTok},
		{"another user's passkey", aliceTok, alice.ID, "PUT", action, bobKey, true, aliceTok},
		{"user not verified (touch only)", aliceTok, alice.ID, "PUT", action, aliceKey, false, aliceTok},
		{"a challenge of another user", bobTok, bob.ID, "PUT", action, aliceKey, true, aliceTok},
	} {
		_, ch := begin(c.beginUsingTok, alice.ID, "PUT", action)
		if err := verify(c.token, c.uid, c.method, c.url, c.key.answer(t, ch, c.userVerified)); err == nil {
			t.Errorf("%s: must be refused", c.name)
		}
	}

	// A refused answer still uses the challenge up: no second try with a better one.
	_, ch = begin(aliceTok, alice.ID, "PUT", action)
	_ = verify(aliceTok, alice.ID, "DELETE", action, aliceKey.answer(t, ch, true))
	if err := verify(aliceTok, alice.ID, "PUT", action, aliceKey.answer(t, ch, true)); err == nil {
		t.Fatal("a challenge must be gone after a refused answer")
	}

	// Begin: only mutating /api/ requests, and only for a user with a passkey.
	for _, bad := range [][2]string{{"GET", action}, {"PUT", "/elsewhere"}, {"PUT", "/api/x y"}} {
		if code, _ := begin(aliceTok, alice.ID, bad[0], bad[1]); code != http.StatusBadRequest {
			t.Errorf("begin %v: %d, want 400", bad, code)
		}
	}
	carol, _ := svc.CreateUser("stepup_passkey_carol", pw, RoleAdmin)
	if code, _ := begin(session(carol), carol.ID, "PUT", action); code != http.StatusConflict {
		t.Errorf("begin without a passkey: %d, want 409", code)
	}

	// The 428 re-prompt tells the UI a passkey can be used.
	rec := httptest.NewRecorder()
	if svc.StepUpWith(rec, req("PUT", action, aliceTok, "", alice.ID), alice.ID, StepUpCreds{}) || rec.Code != http.StatusPreconditionRequired ||
		!strings.Contains(rec.Body.String(), `"passkey":true`) {
		t.Fatalf("428 must offer the passkey: %d %s", rec.Code, rec.Body)
	}
	// A password-only check (the password and 2FA settings) never offers the passkey.
	rec = httptest.NewRecorder()
	if svc.StepUp(rec, alice.ID, "", "") || !strings.Contains(rec.Body.String(), `"passkey":false`) {
		t.Fatalf("a password-only 428 must not offer the passkey: %s", rec.Body)
	}
	// The password path is unchanged.
	if err := svc.VerifyStepUpRequest(req("PUT", action, aliceTok, "", alice.ID), alice.ID, StepUpCreds{CurrentPassword: pw}); err != nil {
		t.Fatalf("password step-up: %v", err)
	}
}
