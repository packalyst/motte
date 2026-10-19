package auth

// Passwordless login with passkeys (WebAuthn / FIDO2), roadmap point 8. ADDITIVE: password + TOTP
// login are untouched; a passkey is simply another way in. Phase 1 here is register + manage (in
// Profile) and discoverable ("usernameless") login. Step-up via passkey is a later phase.
//
// WebAuthn requires the panel be reached over HTTPS on a real domain — the RP ID is derived from
// the browser's Origin. Logging in via a raw IP won't offer passkeys (spec limitation); password
// and TOTP still work there.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// --- in-progress challenge store (short-lived; begin→finish) --------------------------------------

type waChallenge struct {
	data    webauthn.SessionData
	expires time.Time
}

var (
	waMu         sync.Mutex
	waChallenges = map[string]*waChallenge{}
)

func waStoreChallenge(key string, data webauthn.SessionData) {
	waMu.Lock()
	defer waMu.Unlock()
	now := time.Now()
	for k, c := range waChallenges { // opportunistic sweep
		if now.After(c.expires) {
			delete(waChallenges, k)
		}
	}
	waChallenges[key] = &waChallenge{data: data, expires: now.Add(3 * time.Minute)}
}

func waTakeChallenge(key string) (webauthn.SessionData, bool) {
	waMu.Lock()
	defer waMu.Unlock()
	c, ok := waChallenges[key]
	delete(waChallenges, key)
	if !ok || time.Now().After(c.expires) {
		return webauthn.SessionData{}, false
	}
	return c.data, true
}

// --- webauthn.User adapter ------------------------------------------------------------------------

type webauthnUser struct {
	id     int64
	name   string
	handle []byte
	creds  []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.handle }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.name }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// --- storage --------------------------------------------------------------------------------------

var waOnce sync.Once

func (s *Service) ensureWebAuthnTables() {
	waOnce.Do(func() {
		s.db.Exec(`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       INTEGER NOT NULL,
			credential_id BLOB NOT NULL UNIQUE,
			name          TEXT NOT NULL DEFAULT '',
			cred_json     TEXT NOT NULL,
			rpid          TEXT NOT NULL DEFAULT '',
			created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_used_at  TIMESTAMP
		)`)
		s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_wa_cred_user ON webauthn_credentials(user_id)`)
		// Per-user opaque handle = WebAuthn user id (not PII). Added to the existing users table.
		s.db.Exec(`ALTER TABLE users ADD COLUMN webauthn_handle BLOB`)
	})
}

// webauthnHandle returns the user's opaque WebAuthn handle, generating one on first use.
func (s *Service) webauthnHandle(userID int64) ([]byte, error) {
	var h []byte
	if err := s.db.QueryRow(`SELECT webauthn_handle FROM users WHERE id = ?`, userID).Scan(&h); err != nil {
		return nil, err
	}
	if len(h) == 0 {
		h = make([]byte, 32)
		if _, err := rand.Read(h); err != nil {
			return nil, err
		}
		if _, err := s.db.Exec(`UPDATE users SET webauthn_handle = ? WHERE id = ?`, h, userID); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (s *Service) loadCredentials(userID int64) ([]webauthn.Credential, error) {
	rows, err := s.db.Query(`SELECT cred_json FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webauthn.Credential
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if json.Unmarshal([]byte(j), &c) == nil {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

func (s *Service) loadWAUser(userID int64) (*webauthnUser, error) {
	var name string
	if err := s.db.QueryRow(`SELECT username FROM users WHERE id = ?`, userID).Scan(&name); err != nil {
		return nil, err
	}
	h, err := s.webauthnHandle(userID)
	if err != nil {
		return nil, err
	}
	creds, err := s.loadCredentials(userID)
	if err != nil {
		return nil, err
	}
	return &webauthnUser{id: userID, name: name, handle: h, creds: creds}, nil
}

func (s *Service) loadWAUserByHandle(handle []byte) (*webauthnUser, error) {
	var id int64
	var name string
	if err := s.db.QueryRow(`SELECT id, username FROM users WHERE webauthn_handle = ?`, handle).Scan(&id, &name); err != nil {
		return nil, err
	}
	creds, err := s.loadCredentials(id)
	if err != nil {
		return nil, err
	}
	return &webauthnUser{id: id, name: name, handle: append([]byte(nil), handle...), creds: creds}, nil
}

func (s *Service) saveCredential(userID int64, name, rpid string, c *webauthn.Credential) error {
	j, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		name = "Passkey"
	}
	_, err = s.db.Exec(
		`INSERT INTO webauthn_credentials (user_id, credential_id, name, cred_json, rpid, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		userID, c.ID, name, string(j), rpid, time.Now(),
	)
	return err
}

// touchCredential persists the post-login credential (updated sign counter) and the last-used time.
func (s *Service) touchCredential(c *webauthn.Credential) {
	if j, err := json.Marshal(c); err == nil {
		s.db.Exec(`UPDATE webauthn_credentials SET cred_json = ?, last_used_at = ? WHERE credential_id = ?`, string(j), time.Now(), c.ID)
	}
}

// --- RP config (derived from the request Origin) --------------------------------------------------

func (s *Service) newWebAuthn(r *http.Request) (*webauthn.WebAuthn, string, error) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
			scheme = "http"
		}
		origin = scheme + "://" + r.Host
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, "", fmt.Errorf("could not determine request origin")
	}
	rpid := u.Hostname()
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "WireGuard Panel",
		RPID:          rpid,
		RPOrigins:     []string{strings.TrimRight(origin, "/")},
	})
	return wa, rpid, err
}

func (s *Service) currentUser(r *http.Request) (*User, error) {
	tok := helper.SessionToken(r)
	if tok == "" {
		return nil, ErrInvalidSession
	}
	return s.ValidateSession(tok)
}

// --- handlers -------------------------------------------------------------------------------------

// handlePasskeyRegisterBegin (authed) returns creation options for adding a passkey.
func (s *Service) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	s.ensureWebAuthnTables()
	u, err := s.currentUser(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	wa, _, err := s.newWebAuthn(r)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	waUser, err := s.loadWAUser(u.ID)
	if err != nil {
		router.JSONError(w, "could not load user", http.StatusInternalServerError)
		return
	}
	sel := protocol.AuthenticatorSelection{
		ResidentKey:      protocol.ResidentKeyRequirementRequired, // discoverable → passwordless
		UserVerification: protocol.VerificationPreferred,
	}
	options, sessionData, err := wa.BeginRegistration(waUser, webauthn.WithAuthenticatorSelection(sel))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	waStoreChallenge("reg:"+strconv.FormatInt(u.ID, 10), *sessionData)
	router.JSON(w, options)
}

// handlePasskeyRegisterFinish (authed) verifies and stores the new credential. The label comes from
// the ?name= query param; the attestation response is the POST body.
func (s *Service) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	s.ensureWebAuthnTables()
	u, err := s.currentUser(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sessionData, ok := waTakeChallenge("reg:" + strconv.FormatInt(u.ID, 10))
	if !ok {
		router.JSONError(w, "registration expired, start again", http.StatusBadRequest)
		return
	}
	wa, rpid, err := s.newWebAuthn(r)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	waUser, err := s.loadWAUser(u.ID)
	if err != nil {
		router.JSONError(w, "could not load user", http.StatusInternalServerError)
		return
	}
	cred, err := wa.FinishRegistration(waUser, sessionData, r)
	if err != nil {
		router.JSONError(w, "passkey registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if err := s.saveCredential(u.ID, name, rpid, cred); err != nil {
		router.JSONError(w, "could not store passkey", http.StatusInternalServerError)
		return
	}
	events.Audit("auth", "passkey_registered", events.SeverityInfo, u.Username, helper.GetClientIP(r),
		fmt.Sprintf("Passkey %q registered", name))
	router.JSON(w, map[string]bool{"ok": true})
}

// handlePasskeyLoginBegin (public) returns assertion options for discoverable login, plus a
// challengeId the client echoes back on finish (there is no session yet to key the challenge to).
func (s *Service) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	s.ensureWebAuthnTables()
	wa, _, err := s.newWebAuthn(r)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	options, sessionData, err := wa.BeginDiscoverableLogin()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	handle := make([]byte, 16)
	rand.Read(handle)
	id := hex.EncodeToString(handle)
	waStoreChallenge("login:"+id, *sessionData)
	router.JSON(w, map[string]any{"publicKey": options.Response, "challengeId": id})
}

// handlePasskeyLoginFinish (public) verifies the assertion, resolves the user from the credential's
// user handle, and issues a session exactly like a password login (cookie + body token).
func (s *Service) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	s.ensureWebAuthnTables()
	clientIP := helper.GetClientIP(r)
	id := r.URL.Query().Get("challengeId")
	sessionData, ok := waTakeChallenge("login:" + id)
	if !ok {
		router.JSONError(w, "login expired, start again", http.StatusBadRequest)
		return
	}
	wa, _, err := s.newWebAuthn(r)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var matchedID int64
	cred, err := wa.FinishDiscoverableLogin(func(_, userHandle []byte) (webauthn.User, error) {
		waUser, err := s.loadWAUserByHandle(userHandle)
		if err != nil {
			return nil, err
		}
		matchedID = waUser.id
		return waUser, nil
	}, sessionData, r)
	if err != nil || matchedID == 0 {
		events.Audit("auth", "passkey_login_failed", events.SeverityWarning, "", clientIP, "Passkey login failed")
		router.JSONError(w, "passkey login failed", http.StatusUnauthorized)
		return
	}
	s.touchCredential(cred)

	user, err := s.getUser(matchedID)
	if err != nil {
		router.JSONError(w, "could not load user", http.StatusInternalServerError)
		return
	}
	resp, err := s.createSession(*user, clientIP, r.Header.Get("User-Agent"))
	if err != nil {
		router.JSONError(w, "could not create session", http.StatusInternalServerError)
		return
	}
	if exp, perr := time.Parse(time.RFC3339, resp.ExpiresAt); perr == nil {
		helper.SetSessionCookie(w, r, resp.Token, exp)
	}
	events.Audit("auth", "login", events.SeverityInfo, user.Username, clientIP,
		fmt.Sprintf("Passkey login succeeded for %q", user.Username))
	router.JSON(w, resp)
}

// handleListPasskeys (authed) lists the caller's passkeys (metadata only).
func (s *Service) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	s.ensureWebAuthnTables()
	u, err := s.currentUser(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := s.db.Query(`SELECT id, name, created_at, COALESCE(last_used_at, '') FROM webauthn_credentials WHERE user_id = ? ORDER BY id`, u.ID)
	if err != nil {
		router.JSONError(w, "could not list passkeys", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type pk struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		CreatedAt  string `json:"createdAt"`
		LastUsedAt string `json:"lastUsedAt,omitempty"`
	}
	list := []pk{}
	for rows.Next() {
		var p pk
		if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.LastUsedAt); err == nil {
			list = append(list, p)
		}
	}
	router.JSON(w, list)
}

// handleDeletePasskey (authed) removes one of the caller's passkeys by id.
func (s *Service) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	s.ensureWebAuthnTables()
	u, err := s.currentUser(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(router.ExtractPathParam(r, "/api/auth/passkeys/"), 10, 64)
	if err != nil {
		router.JSONError(w, "invalid passkey id", http.StatusBadRequest)
		return
	}
	res, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, u.ID)
	if err != nil {
		router.JSONError(w, "could not delete passkey", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		router.JSONError(w, "passkey not found", http.StatusNotFound)
		return
	}
	events.Audit("auth", "passkey_deleted", events.SeverityInfo, u.Username, helper.GetClientIP(r),
		fmt.Sprintf("Passkey %d removed", id))
	router.JSON(w, map[string]bool{"ok": true})
}
