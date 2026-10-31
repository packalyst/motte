package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// ErrStepUpTOTPRequired is returned by verifyStepUp when the user has 2FA enabled but supplied
// no TOTP code. Callers surface it distinctly so the UI can prompt for the authenticator code
// (rather than reporting a wrong password).
var ErrStepUpTOTPRequired = errors.New("2fa code required")

// verifyStepUp checks the password step-up of a user. It always requires the current password — so
// a stolen session token alone is never sufficient — and, when the user has TOTP 2FA enabled,
// additionally a fresh, non-replayed TOTP code.
//
// Fail-closed for 2FA users: a missing code returns ErrStepUpTOTPRequired and an invalid/replayed
// code is rejected. Users WITHOUT 2FA are unaffected (password-only), so routing an action
// through step-up never locks anyone out who hasn't opted into 2FA.
func (s *Service) verifyStepUp(userID int64, password, totpCode string) error {
	// Password first (also upgrades a legacy hash on success).
	if err := s.VerifyPassword(userID, password); err != nil {
		return err
	}

	var totpEnabled int
	var totpSecretEnc sql.NullString
	if err := s.db.QueryRow(
		"SELECT COALESCE(totp_enabled, 0), totp_secret_enc FROM users WHERE id = ?", userID,
	).Scan(&totpEnabled, &totpSecretEnc); err != nil {
		return errors.New("user not found")
	}
	if totpEnabled != 1 {
		return nil // no 2FA — password step-up is sufficient
	}
	if totpCode == "" {
		return ErrStepUpTOTPRequired
	}
	return verifyTOTP(userID, totpSecretEnc, totpCode)
}

// StepUpCreds is what a sensitive request carries to re-authenticate the caller: the current
// password (+ a 2FA code when 2FA is on), or a passkey answer made for exactly that request. Every
// request body that takes a step-up embeds it.
type StepUpCreds struct {
	CurrentPassword string          `json:"currentPassword"`
	TotpCode        string          `json:"totpCode"`
	Passkey         json.RawMessage `json:"passkey,omitempty"`
}

// StepUpOption adjusts what one step-up accepts.
type StepUpOption func(*stepUpPolicy)

type stepUpPolicy struct {
	passwordOnly bool
	grace        *GraceWindow
}

// PasswordOnly takes the password (+ 2FA code) only, never a passkey: for the checks about the
// credentials themselves (changing the password, 2FA, adding a passkey).
func PasswordOnly(p *stepUpPolicy) { p.passwordOnly = true }

// WithGrace passes without credentials while the session is inside g, and opens g on success.
func WithGrace(g *GraceWindow) StepUpOption {
	return func(p *stepUpPolicy) { p.grace = g }
}

var errStepUpRequired = errors.New("step-up re-authentication required")

// RequireStepUp is the panel's one step-up: every sensitive action re-authenticates its caller
// here. It passes inside the option's grace window; otherwise it takes the passkey answer when one
// is given (made for exactly this request and session, see verifyPasskeyStepUp; unless
// PasswordOnly), else the current password plus a fresh 2FA code when 2FA is on. On success it
// returns true (and opens the grace window, if any). On failure it returns false having answered:
// 429 while the password or 2FA code is locked out (re-prompting can't help until it expires),
// else 428 — never 401, which the UI treats as "signed out" — carrying {error, stepup: true,
// totp, passkey}: whether to ask for a 2FA code, and whether a passkey works here. A failed try
// is audited; a request without any credentials (the first try, before the UI asked) is only
// answered: it counts no attempt.
func (s *Service) RequireStepUp(w http.ResponseWriter, r *http.Request, userID int64, c StepUpCreds, opts ...StepUpOption) bool {
	var pol stepUpPolicy
	for _, o := range opts {
		o(&pol)
	}
	if pol.passwordOnly {
		c.Passkey = nil
	}
	if userID == 0 {
		auditStepUp(r, userID, "no signed-in user")
		writeStepUpRequired(w, errStepUpRequired.Error(), false, false)
		return false
	}
	if pol.grace != nil && pol.grace.use(r) {
		return true
	}
	if c.CurrentPassword == "" && len(c.Passkey) == 0 {
		s.writeStepUp(w, userID, errStepUpRequired, !pol.passwordOnly)
		return false
	}
	var err error
	if len(c.Passkey) > 0 {
		err = s.verifyPasskeyStepUp(r, userID, c.Passkey)
	} else {
		err = s.verifyStepUp(userID, c.CurrentPassword, c.TotpCode)
	}
	if err != nil {
		if !errors.Is(err, ErrStepUpTOTPRequired) { // the right password, the code still to come
			how := "password"
			if len(c.Passkey) > 0 {
				how = "passkey"
			}
			auditStepUp(r, userID, how)
		}
		s.writeStepUp(w, userID, err, !pol.passwordOnly)
		return false
	}
	if pol.grace != nil {
		pol.grace.open(r)
	}
	return true
}

// RequireStepUp runs the step-up for the request's signed-in caller: for packages that decode the
// credentials into their own request body. Fails closed (428) without a caller or auth service.
func RequireStepUp(w http.ResponseWriter, r *http.Request, c StepUpCreds, opts ...StepUpOption) bool {
	s, p := GetService(), router.CurrentUser(r)
	if s == nil || p == nil {
		auditStepUp(r, 0, "no signed-in user")
		writeStepUpRequired(w, errStepUpRequired.Error(), false, false)
		return false
	}
	return s.RequireStepUp(w, r, p.UserID, c, opts...)
}

// writeStepUp answers a failed step-up (see RequireStepUp).
func (s *Service) writeStepUp(w http.ResponseWriter, userID int64, err error, passkeyOK bool) {
	if tooManyAttempts(w, err) {
		return
	}
	msg := err.Error()
	if errors.Is(err, ErrStepUpTOTPRequired) {
		msg = "two-factor authentication code required"
	}
	writeStepUpRequired(w, msg, s.TOTPEnabled(userID), passkeyOK && s.HasPasskey(userID))
}

func writeStepUpRequired(w http.ResponseWriter, msg string, totp, passkey bool) {
	router.JSONWithStatus(w, map[string]any{
		"error":   msg,
		"stepup":  true,
		"totp":    totp,
		"passkey": passkey,
	}, http.StatusPreconditionRequired)
}

// auditStepUp records a failed step-up: whose, which request, and with what.
func auditStepUp(r *http.Request, userID int64, how string) {
	actor := ""
	if p := router.CurrentUser(r); p != nil {
		actor = p.Username
	}
	events.Audit("auth", "stepup_failed", events.SeverityWarning, actor, helper.GetClientIP(r),
		fmt.Sprintf("Step-up failed for user #%d on %s %s (%s)", userID, r.Method, r.URL.Path, how))
}

// StepUpRequest is RequireStepUp with the credentials read from the request's JSON body, for the
// caller resolved from the router principal: registered as router.StepUp, so packages that can't
// import auth gate their sensitive actions with it.
func (s *Service) StepUpRequest(w http.ResponseWriter, r *http.Request) bool {
	var creds StepUpCreds
	if r.Body != nil {
		// An absent/empty/garbled body leaves creds zero-valued: a 428 prompt, not an error.
		_ = json.NewDecoder(r.Body).Decode(&creds)
	}
	var userID int64
	if p := router.CurrentUser(r); p != nil {
		userID = p.UserID
	}
	return s.RequireStepUp(w, r, userID, creds)
}

// TOTPEnabled reports whether the user has 2FA enabled. Used by handlers that surface to the UI
// whether a step-up prompt should also collect an authenticator code.
func (s *Service) TOTPEnabled(userID int64) bool {
	var enabled int
	if err := s.db.QueryRow("SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?", userID).Scan(&enabled); err != nil {
		return false
	}
	return enabled == 1
}
