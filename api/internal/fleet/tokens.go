package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
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

// CreateToken mints a one-time enrollment token valid for ttl. panelHost is the direct
// origin address the agent will dial for mTLS (an IP the operator picked) — recorded so
// the install endpoint can bake it into the script's --panel later.
func (s *Service) CreateToken(label string, ttl time.Duration, panelHost string) (*Token, error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	val, err := newTokenValue()
	if err != nil {
		return nil, err
	}
	exp := time.Now().Add(ttl).UTC()
	if _, err := s.db.Exec(
		`INSERT INTO fleet_tokens (token_hash, label, panel_host, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		hashToken(val), label, panelHost, exp.Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return nil, err
	}
	return &Token{Plaintext: val, Label: label, ExpiresAt: exp}, nil
}

// PendingToken is an outstanding (unused, unexpired) enrollment token — metadata
// only, NEVER the secret or its hash. Shown as a "waiting for agent" card until the
// token is redeemed (an agent enrolls) or it expires.
type PendingToken struct {
	ID        int64     `json:"id"` // rowid, so the admin can cancel it
	Label     string    `json:"label"`
	PanelHost string    `json:"panel_host,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ListPendingTokens returns outstanding enrollment tokens (unused + unexpired),
// newest first. Returns metadata only — never the token value or its hash.
func (s *Service) ListPendingTokens() ([]PendingToken, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT rowid, label, COALESCE(panel_host,''), created_at, expires_at
		 FROM fleet_tokens WHERE used = 0 AND expires_at > ? ORDER BY created_at DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PendingToken{}
	for rows.Next() {
		var p PendingToken
		var created, expires string
		if err := rows.Scan(&p.ID, &p.Label, &p.PanelHost, &created, &expires); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339, created)
		p.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePendingToken cancels an outstanding (still-unused) enrollment token by rowid.
func (s *Service) DeletePendingToken(id int64) error {
	_, err := s.db.Exec(`DELETE FROM fleet_tokens WHERE rowid = ? AND used = 0`, id)
	return err
}

// lookupToken returns the recorded panel_host for a token that is live (exists, unused,
// unexpired). live=false otherwise. Does NOT consume the token (enroll does that).
func (s *Service) lookupToken(plaintext string) (panelHost string, live bool) {
	if plaintext == "" {
		return "", false
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var host sql.NullString
	err := s.db.QueryRow(
		`SELECT panel_host FROM fleet_tokens WHERE token_hash = ? AND used = 0 AND expires_at > ?`,
		hashToken(plaintext), now,
	).Scan(&host)
	if err != nil {
		return "", false
	}
	return host.String, true
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
