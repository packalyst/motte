package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

var errInvalidToken = errors.New("invalid, used, or expired enrollment token")

// Token is a one-time enrollment credential. The plaintext is returned ONCE at
// creation (shown to the admin, baked into the install command) and never stored;
// only its SHA-256 hash is persisted.
type Token struct {
	Plaintext string    `json:"token"`
	Label     string    `json:"label"`
	ExpiresAt time.Time `json:"expires_at"`
}

func newTokenValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// CreateToken mints a one-time enrollment token valid for ttl.
func (s *Service) CreateToken(label string, ttl time.Duration) (*Token, error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	val, err := newTokenValue()
	if err != nil {
		return nil, err
	}
	exp := time.Now().Add(ttl).UTC()
	if _, err := s.db.Exec(
		`INSERT INTO fleet_tokens (token_hash, label, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		hashToken(val), label, exp.Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return nil, err
	}
	return &Token{Plaintext: val, Label: label, ExpiresAt: exp}, nil
}

// redeemToken atomically validates + consumes a token. A single UPDATE guarded by
// (used=0 AND not expired) means only one concurrent caller can ever win, so a
// token can't be used twice. Returns the token's label.
func (s *Service) redeemToken(plaintext string) (string, error) {
	h := hashToken(plaintext)
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(
		`UPDATE fleet_tokens SET used = 1, used_at = ? WHERE token_hash = ? AND used = 0 AND expires_at > ?`,
		now, h, now,
	)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", errInvalidToken
	}
	var label string
	_ = s.db.QueryRow(`SELECT label FROM fleet_tokens WHERE token_hash = ?`, h).Scan(&label)
	return label, nil
}
