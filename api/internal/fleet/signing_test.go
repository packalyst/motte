package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// TestVerifyChecksumsSig exercises the fail-closed release-signature check with a real
// ed25519 keypair: a good signature verifies; tamper, wrong key, and malformed inputs all
// fail; and an empty/garbage baked-in public key never passes.
func TestVerifyChecksumsSig(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("abc123  wgscout-linux-amd64\ndef456  wgscout-linux-arm64\n")
	good := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))

	orig := signPubKey
	defer func() { signPubKey = orig }()

	// Enabled with the matching public key.
	signPubKey = base64.StdEncoding.EncodeToString(pub)
	if !signingEnabled() {
		t.Fatal("signingEnabled() should be true with a key set")
	}
	if err := verifyChecksumsSig(msg, []byte(good)); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// A trailing newline on the base64 signature must still verify (release files have one).
	if err := verifyChecksumsSig(msg, []byte(good+"\n")); err != nil {
		t.Errorf("valid signature with trailing newline rejected: %v", err)
	}
	// Tampered checksums.
	if err := verifyChecksumsSig(append([]byte("x"), msg...), []byte(good)); err == nil {
		t.Error("tampered checksums must fail")
	}
	// Malformed signature (not base64 / wrong length).
	if err := verifyChecksumsSig(msg, []byte("!!not-base64!!")); err == nil {
		t.Error("malformed signature must fail")
	}
	if err := verifyChecksumsSig(msg, []byte(base64.StdEncoding.EncodeToString([]byte("short")))); err == nil {
		t.Error("wrong-length signature must fail")
	}
	// A signature from a DIFFERENT key must not verify.
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	other := base64.StdEncoding.EncodeToString(ed25519.Sign(priv2, msg))
	if err := verifyChecksumsSig(msg, []byte(other)); err == nil {
		t.Error("signature from a different key must fail")
	}

	// A garbage baked-in public key must fail closed, never pass.
	signPubKey = "not-a-valid-key"
	if err := verifyChecksumsSig(msg, []byte(good)); err == nil {
		t.Error("invalid baked-in public key must fail closed")
	}

	// Empty key => signing disabled.
	signPubKey = ""
	if signingEnabled() {
		t.Error("signingEnabled() should be false with no key")
	}
}
