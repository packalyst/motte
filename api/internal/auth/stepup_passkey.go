package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"api/internal/bounded"
	"api/internal/helper"
	"api/internal/router"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// A passkey step-up: instead of the password (+ 2FA code), a sensitive request carries a passkey
// answer. The challenge it answers was made for one user, one login session and one action (the
// request's method and URL), is used up when checked, and expires with helper.PasskeyChallengeTTL;
// the passkey must verify the user (face, fingerprint or the device PIN), so on its own it is two
// factors, and it can't be phished.

var errPasskeyStepUp = errors.New("passkey confirmation failed, try again")

// stepUpChallenge is a passkey step-up waiting for its answer.
type stepUpChallenge struct {
	userID int64
	action string // "METHOD /path?query" of the one request it may confirm
	data   webauthn.SessionData
}

// One per login session (keyed by the session's hash): starting another replaces it.
var waStepUps = bounded.New[string, stepUpChallenge](helper.MaxTrackedSignInKeys, bounded.Refuse)

// stepUpAction names the request a passkey answer confirms.
func stepUpAction(method, uri string) string { return strings.ToUpper(method) + " " + uri }

// validStepUpAction accepts only a panel API request: a mutating method and an /api/ URL.
func validStepUpAction(method, uri string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	return strings.HasPrefix(uri, "/api/") && len(uri) <= 512 && !strings.ContainsAny(uri, " \r\n")
}

// HasPasskey reports whether the user has registered a passkey (the UI then offers it for step-up).
func (s *Service) HasPasskey(userID int64) bool {
	s.ensureWebAuthnTables()
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&n)
	return n > 0
}

// handlePasskeyStepUpBegin starts a passkey step-up for one request of the caller's session.
// POST /api/auth/stepup/passkey {method, url} → {publicKey}. Allowed on a locked session: unlocking
// is such a request.
func (s *Service) handlePasskeyStepUpBegin(w http.ResponseWriter, r *http.Request) {
	s.ensureWebAuthnTables()
	p := router.CurrentUser(r)
	token := helper.SessionToken(r)
	if p == nil || p.UserID == 0 || token == "" {
		router.JSONError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	var req struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if !validStepUpAction(req.Method, req.URL) {
		router.JSONError(w, "invalid action", http.StatusBadRequest)
		return
	}
	user, err := s.loadWAUser(p.UserID)
	if err != nil || len(user.creds) == 0 {
		router.JSONError(w, "no passkey registered", http.StatusConflict)
		return
	}
	wa, _, err := s.newWebAuthn(r)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	options, data, err := wa.BeginLogin(user, webauthn.WithUserVerification(passkeyUV))
	if err != nil {
		router.JSONError(w, "could not start the passkey confirmation", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	data.Expires = now.Add(helper.PasskeyChallengeTTL)
	c := stepUpChallenge{userID: p.UserID, action: stepUpAction(req.Method, req.URL), data: *data}
	if !waStepUps.Update(hashToken(token), now, func(v *stepUpChallenge, _ bool) time.Time {
		*v = c
		return data.Expires
	}) {
		router.JSONError(w, "too many confirmations in progress, try again shortly", http.StatusServiceUnavailable)
		return
	}
	router.JSON(w, map[string]any{"publicKey": options.Response})
}

// verifyPasskeyStepUp checks a passkey answer for request r by userID: the challenge of r's
// session (used up here, whatever the outcome) must be the caller's, made for exactly this
// request and not expired, and the answer must come from one of the caller's own passkeys with
// the user verified.
func (s *Service) verifyPasskeyStepUp(r *http.Request, userID int64, answer json.RawMessage) error {
	token := helper.SessionToken(r)
	if token == "" {
		return errPasskeyStepUp
	}
	c, ok := waStepUps.Take(hashToken(token), time.Now())
	if !ok || c.userID != userID || c.action != stepUpAction(r.Method, r.URL.RequestURI()) || !time.Now().Before(c.data.Expires) {
		return errPasskeyStepUp
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(answer)
	if err != nil {
		return errPasskeyStepUp
	}
	user, err := s.loadWAUser(userID)
	if err != nil {
		return errPasskeyStepUp
	}
	wa, _, err := s.newWebAuthn(r)
	if err != nil {
		return errPasskeyStepUp
	}
	// The challenge requires user verification, which the library enforces; checked here too, on
	// this answer's own flags.
	cred, err := wa.ValidateLogin(user, c.data, parsed)
	if err != nil || !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		return errPasskeyStepUp
	}
	s.touchCredential(cred)
	return nil
}
