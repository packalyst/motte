package fleet

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// signPubKey is the base64-encoded ed25519 PUBLIC key used to verify release signatures. It
// is injected at link time via -ldflags "-X api/internal/fleet.signPubKey=<b64>" from the
// committed signing.pub. When empty (no key built in) signature enforcement is DISABLED, so
// unsigned/legacy releases still work; once a key is baked in, every release the panel serves
// MUST carry a valid checksums.txt.sig. The matching PRIVATE key never exists on the panel.
var signPubKey string

// signingEnabled reports whether the panel was built with a signing public key and must
// therefore require+verify a release signature.
func signingEnabled() bool { return strings.TrimSpace(signPubKey) != "" }

// verifyChecksumsSig checks that sigB64 is a valid ed25519 signature by signPubKey over the
// exact bytes of checksums. Fail-closed: any decode/length/verify problem is an error, and
// the caller must NOT trust the checksums (and therefore not serve the release).
func verifyChecksumsSig(checksums, sigB64 []byte) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signPubKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		// A misconfigured baked-in key must never silently pass verification.
		return fmt.Errorf("panel signing public key is invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release signature is malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), checksums, sig) {
		return fmt.Errorf("release signature does not verify against the panel's signing key")
	}
	return nil
}
