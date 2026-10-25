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
	msg := []byte("abc123  motte-agent-linux-amd64\ndef456  motte-agent-linux-arm64\n")
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

// TestVerifyChecksumsSigKeyRollover checks that with two baked-in keys a signature from EITHER
// verifies (so a rotation can bake {old,new} and retire old later), while a signature from a
// third, un-baked key still fails.
func TestVerifyChecksumsSigKeyRollover(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	_, priv3, _ := ed25519.GenerateKey(rand.Reader) // not baked in
	msg := []byte("abc123  motte-agent-linux-amd64\n")

	orig := signPubKey
	defer func() { signPubKey = orig }()
	// Two keys, comma-separated as the build plumbing bakes them.
	signPubKey = base64.StdEncoding.EncodeToString(pub1) + "," + base64.StdEncoding.EncodeToString(pub2)

	if !signingEnabled() {
		t.Fatal("signingEnabled() should be true with keys set")
	}
	for name, priv := range map[string]ed25519.PrivateKey{"first key": priv1, "second key": priv2} {
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
		if err := verifyChecksumsSig(msg, []byte(sig)); err != nil {
			t.Errorf("signature from the %s should verify during rollover: %v", name, err)
		}
	}
	// A key that isn't baked in must not verify.
	bad := base64.StdEncoding.EncodeToString(ed25519.Sign(priv3, msg))
	if err := verifyChecksumsSig(msg, []byte(bad)); err == nil {
		t.Error("signature from an un-baked key must fail")
	}

	// A present-but-unparseable key set must fail closed, not fall through to no-verify.
	signPubKey = "garbage-1,garbage-2"
	if !signingEnabled() {
		t.Error("signingEnabled() stays true for a present (if malformed) key string")
	}
	if err := verifyChecksumsSig(msg, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv1, msg)))); err == nil {
		t.Error("unparseable baked-in keys must fail closed")
	}
}
