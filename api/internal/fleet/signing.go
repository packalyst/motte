package fleet

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// signPubKey holds the base64-encoded ed25519 PUBLIC key(s) used to verify release
// signatures, injected at link time via -ldflags "-X api/internal/fleet.signPubKey=<b64>"
// from the committed signing.pub. It may carry SEVERAL keys separated by commas/whitespace:
// during a key rollover both the retiring and the new key are baked in, and a release
// verifies if ANY of them accepts it, so agents keep updating across the rotation. When empty
// (no key built in) signature enforcement is DISABLED, so unsigned/legacy releases still work;
// once any key is baked in, every release the panel serves MUST carry a valid
// checksums.txt.sig. The matching PRIVATE key never exists on the panel.
var signPubKey string

// signingEnabled reports whether the panel was built with a signing public key and must
// therefore require+verify a release signature. It is based on a key STRING being present
// (not on it parsing): a present-but-malformed key must fail closed at verification, never
// silently disable enforcement.
func signingEnabled() bool { return strings.TrimSpace(signPubKey) != "" }

// signingPubKeys parses the configured key list into usable ed25519 public keys, skipping any
// malformed entry so one bad key can't disable the others.
func signingPubKeys() []ed25519.PublicKey {
	fields := strings.FieldsFunc(signPubKey, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	keys := make([]ed25519.PublicKey, 0, len(fields))
	for _, f := range fields {
		pub, err := base64.StdEncoding.DecodeString(f)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		keys = append(keys, ed25519.PublicKey(pub))
	}
	return keys
}

// verifyChecksumsSig checks that sigB64 is a valid ed25519 signature over the exact bytes of
// checksums by any one of the baked-in public keys. Fail-closed: a present-but-unparseable
// key set, a malformed signature, or no key accepting it are all errors, and the caller must
// NOT trust the checksums (and therefore not serve the release).
func verifyChecksumsSig(checksums, sigB64 []byte) error {
	keys := signingPubKeys()
	if len(keys) == 0 {
		// A key string was provided (callers gate on signingEnabled) but none parsed — a
		// misconfigured baked-in key must never silently pass verification.
		return fmt.Errorf("panel signing public key is invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release signature is malformed")
	}
	for _, pub := range keys {
		if ed25519.Verify(pub, checksums, sig) {
			return nil
		}
	}
	return fmt.Errorf("release signature does not verify against any of the panel's signing keys")
}
