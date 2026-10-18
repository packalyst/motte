package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Password hashing is centralised here so every call site (login, create user, change
// password, step-up re-auth, disable-2FA) shares one implementation.
//
// New hashes use Argon2id — a memory-hard KDF that resists GPU/ASIC cracking far better
// than bcrypt — matching the Argon2id we already use to seal backups (ADR-0005). Existing
// bcrypt hashes still verify, and a correct login/step-up transparently re-hashes them to
// Argon2id (migrate-on-verify), so the fleet converges without forcing a password reset.
//
// Parameters follow the OWASP Password Storage guidance for Argon2id (memory-first). They
// are encoded into every hash (PHC string), so raising them later only affects new hashes
// and triggers an automatic re-hash of weaker ones on the next successful verify.
const (
	argonTimeCost  = 3         // iterations
	argonMemoryKiB = 64 * 1024 // 64 MiB
	argonKeyLen    = 32
	argonSaltLen   = 16
)

// argonThreads is the parallelism (lanes). Capped at 4 and at the CPU count so hashing
// never asks for more lanes than the host can run; the value is stored in each hash, so
// verification on a differently-sized host still reproduces the digest.
var argonThreads = func() uint8 {
	n := runtime.NumCPU()
	switch {
	case n < 1:
		return 1
	case n > 4:
		return 4
	default:
		return uint8(n)
	}
}()

var (
	errInvalidHash         = errors.New("auth: hash is not in a recognised format")
	errIncompatibleVersion = errors.New("auth: incompatible argon2 version")
)

// hashPassword returns a PHC-encoded Argon2id hash of password.
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt generation failed: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTimeCost, argonMemoryKiB, argonThreads, argonKeyLen)
	return encodeArgon2(salt, key, argonMemoryKiB, argonTimeCost, argonThreads), nil
}

// encodeArgon2 renders the standard PHC string:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<b64 salt>$<b64 hash>
func encodeArgon2(salt, key []byte, memory, time uint32, threads uint8) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// verifyPassword checks password against a stored hash (Argon2id or legacy bcrypt).
//
//   - ok:          the password matches.
//   - needsRehash: the stored hash is legacy bcrypt, or Argon2id below current parameters,
//     so the caller should re-hash with hashPassword and persist it.
//
// It is constant-time within each algorithm and never leaks which branch ran via its error.
func verifyPassword(password, encoded string) (ok bool, needsRehash bool, err error) {
	switch {
	case strings.HasPrefix(encoded, "$argon2id$"):
		return verifyArgon2(password, encoded)
	case strings.HasPrefix(encoded, "$2"): // bcrypt: $2a$ / $2b$ / $2y$
		if e := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password)); e != nil {
			return false, false, nil // mismatch or malformed legacy hash → treat as mismatch
		}
		return true, true, nil // correct → upgrade to Argon2id
	default:
		return false, false, errInvalidHash
	}
}

// verifyArgon2 parses a PHC Argon2id string, recomputes the digest with the parameters it
// carries, and compares in constant time.
func verifyArgon2(password, encoded string) (ok bool, needsRehash bool, err error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false, errInvalidHash
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, false, errInvalidHash
	}
	if version != argon2.Version {
		return false, false, errIncompatibleVersion
	}
	var memory, time uint32
	var threads uint8
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, false, errInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false, errInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, false, errInvalidHash
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	// Re-hash if the stored security parameters are weaker than the current policy
	// (parallelism is host-dependent and deliberately not a rehash trigger).
	needsRehash = memory < argonMemoryKiB || time < argonTimeCost
	return true, needsRehash, nil
}

// dummySalt is a fixed, non-secret salt used only to spend one Argon2id computation on the
// unknown-user login path, so its timing is comparable to a real verification (user
// enumeration resistance). Its value is irrelevant; it only needs to be ≥8 bytes.
var dummySalt = []byte("wgpanel-timing-equalizer")

// dummyVerify performs one Argon2id computation and discards it. Call it when no user row
// was found so an attacker cannot distinguish "no such user" from "wrong password" by timing.
func dummyVerify(password string) {
	_ = argon2.IDKey([]byte(password), dummySalt, argonTimeCost, argonMemoryKiB, argonThreads, argonKeyLen)
}

// upgradeHash re-hashes an already-verified password with the current Argon2id parameters
// and stores it. Best-effort: used to migrate legacy bcrypt (or weaker-parameter) hashes on
// a successful verify; a failure here is logged but never fails the authentication.
func (s *Service) upgradeHash(userID int64, password string) {
	enc, err := hashPassword(password)
	if err != nil {
		log.Printf("auth: password re-hash failed for user %d: %v", userID, err)
		return
	}
	if _, err := s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", enc, userID); err != nil {
		log.Printf("auth: password hash upgrade persist failed for user %d: %v", userID, err)
	}
}
