package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"api/internal/router"
)

// ErrStepUpTOTPRequired is returned by VerifyStepUp when the user has 2FA enabled but supplied
// no TOTP code. Callers surface it distinctly so the UI can prompt for the authenticator code
// (rather than reporting a wrong password).
var ErrStepUpTOTPRequired = errors.New("2fa code required")

// VerifyStepUp re-authenticates a user for a sensitive, session-authorized action. It always
// requires the current password — so a stolen session token alone is never sufficient — and,
// when the user has TOTP 2FA enabled, additionally requires a fresh, non-replayed TOTP code.
//
// Fail-closed for 2FA users: a missing code returns ErrStepUpTOTPRequired and an invalid/replayed
// code is rejected. Users WITHOUT 2FA are unaffected (password-only), so routing an action
// through step-up never locks anyone out who hasn't opted into 2FA.
func (s *Service) VerifyStepUp(userID int64, password, totpCode string) error {
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

// StepUp re-authenticates the caller for a sensitive action from the request-supplied password
// and TOTP code. On success it returns true. On failure it writes a 428 (Precondition Required)
// response — never 401 — carrying {error, stepup:true, totp:<bool>}, so a wrong credential
// re-prompts in place instead of tripping the client's 401 auto-logout; the `totp` flag tells
// the UI whether to render an authenticator-code field. While the password or 2FA code is locked
// out after too many failures it writes a 429 instead (re-prompting can't help until it expires).
// It takes the password only: for the checks about the password itself (changing it, 2FA, adding a
// passkey). Everything else uses StepUpWith, which takes a passkey too.
func (s *Service) StepUp(w http.ResponseWriter, callerID int64, password, totpCode string) bool {
	return s.answerStepUp(w, callerID, s.VerifyStepUp(callerID, password, totpCode), false)
}

// StepUpCreds is what a sensitive request carries to re-authenticate the caller: the current
// password (+ a 2FA code when 2FA is on), or a passkey answer made for exactly that request.
type StepUpCreds struct {
	CurrentPassword string          `json:"currentPassword"`
	TotpCode        string          `json:"totpCode"`
	Passkey         json.RawMessage `json:"passkey,omitempty"`
}

// VerifyStepUpRequest re-authenticates userID for request r: by the passkey answer when one is
// given (see verifyPasskeyStepUp; a failed one is audited), otherwise as VerifyStepUp.
func (s *Service) VerifyStepUpRequest(r *http.Request, userID int64, c StepUpCreds) error {
	if len(c.Passkey) == 0 {
		return s.VerifyStepUp(userID, c.CurrentPassword, c.TotpCode)
	}
	if err := s.verifyPasskeyStepUp(r, userID, c.Passkey); err != nil {
		auditStepUpPasskey(r, userID)
		return err
	}
	return nil
}

// StepUpWith is StepUp for a request's creds, a passkey answer included.
func (s *Service) StepUpWith(w http.ResponseWriter, r *http.Request, userID int64, c StepUpCreds) bool {
	return s.answerStepUp(w, userID, s.VerifyStepUpRequest(r, userID, c), true)
}

// answerStepUp turns a step-up result into the response contract: true on success; otherwise a
// 429 while locked out, else the 428 re-prompt (see StepUp), which says whether a passkey would
// do (passkeyOK: this check takes one, and the user has one).
func (s *Service) answerStepUp(w http.ResponseWriter, callerID int64, err error, passkeyOK bool) bool {
	if err == nil {
		return true
	}
	if tooManyAttempts(w, err) { // locked out: re-prompting can't help until it expires
		return false
	}
	msg := err.Error()
	if errors.Is(err, ErrStepUpTOTPRequired) {
		msg = "two-factor authentication code required"
	}
	router.JSONWithStatus(w, map[string]interface{}{
		"error":   msg,
		"stepup":  true,
		"totp":    s.TOTPEnabled(callerID),
		"passkey": passkeyOK && s.HasPasskey(callerID),
	}, http.StatusPreconditionRequired)
	return false
}

// StepUpRequest re-authenticates the caller of a session-authorized request for a sensitive
// action. It reads {currentPassword, totpCode} from the JSON body and resolves the caller from the
// router principal. On success it returns true; on ANY failure (no principal, or a bad/empty
// credential) it writes the standard 428 step-up response — never 401 — and returns false, so the
// UI prompts in place instead of logging out. Reusable by any package guarding a destructive
// action: `if a := auth.GetService(); a != nil && !a.StepUpRequest(w, r) { return }`.
func (s *Service) StepUpRequest(w http.ResponseWriter, r *http.Request) bool {
	p := router.CurrentUser(r)
	if p == nil || p.UserID == 0 {
		router.JSONWithStatus(w, map[string]interface{}{
			"error":  "step-up re-authentication required",
			"stepup": true,
			"totp":   false,
		}, http.StatusPreconditionRequired)
		return false
	}
	var creds StepUpCreds
	if r.Body != nil {
		// An absent/empty/garbled body leaves creds zero-valued, which stepUp turns into a 428
		// prompt rather than an error.
		_ = json.NewDecoder(r.Body).Decode(&creds)
	}
	return s.StepUpWith(w, r, p.UserID, creds)
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
