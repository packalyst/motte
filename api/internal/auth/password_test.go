package auth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	const pw = "Correct-Horse-Battery-9!"

	enc, err := hashPassword(pw)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$") {
		t.Fatalf("not a v19 Argon2id PHC string: %q", enc)
	}

	ok, needsRehash, err := verifyPassword(pw, enc)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("correct password rejected")
	}
	if needsRehash {
		t.Fatal("freshly hashed password should not need a re-hash")
	}

	ok, _, err = verifyPassword("wrong-password", enc)
	if err != nil {
		t.Fatalf("verifyPassword(wrong): %v", err)
	}
	if ok {
		t.Fatal("wrong password accepted")
	}
}

func TestHashPasswordUsesFreshSalt(t *testing.T) {
	a, _ := hashPassword("same-input")
	b, _ := hashPassword("same-input")
	if a == b {
		t.Fatal("two hashes of the same password are identical — salt is not random")
	}
}

func TestVerifyLegacyBcryptTriggersRehash(t *testing.T) {
	const pw = "Legacy-Bcrypt-1!"
	legacy, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}

	ok, needsRehash, err := verifyPassword(pw, string(legacy))
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("correct password against bcrypt hash rejected")
	}
	if !needsRehash {
		t.Fatal("a legacy bcrypt hash must be flagged for re-hash to Argon2id")
	}

	if ok, _, _ := verifyPassword("nope", string(legacy)); ok {
		t.Fatal("wrong password accepted against bcrypt hash")
	}
}

func TestVerifyWeakArgon2TriggersRehash(t *testing.T) {
	const pw = "Weak-Params-2!"
	// A valid Argon2id hash deliberately computed below the current memory policy.
	salt := []byte("0123456789abcdef")
	weakMem := uint32(8 * 1024) // 8 MiB < argonMemoryKiB
	key := argon2.IDKey([]byte(pw), salt, argonTimeCost, weakMem, argonThreads, argonKeyLen)
	enc := encodeArgon2(salt, key, weakMem, argonTimeCost, argonThreads)

	ok, needsRehash, err := verifyPassword(pw, enc)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("correct password against weak-param hash rejected")
	}
	if !needsRehash {
		t.Fatal("an under-policy Argon2id hash must be flagged for re-hash")
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2id$v=19$bogus", "$argon2id$v=99$m=65536,t=3,p=1$c2FsdA$aGFzaA"} {
		ok, _, err := verifyPassword("whatever", bad)
		if ok {
			t.Fatalf("malformed hash %q was accepted", bad)
		}
		if err == nil {
			t.Fatalf("malformed hash %q returned no error", bad)
		}
	}
}

func TestDummyVerifyNoPanic(t *testing.T) {
	dummyVerify("anything") // must simply spend time without panicking
}
