package auth

import (
	"database/sql"
	"errors"
	"net/http"

	"api/internal/helper"
	"api/internal/router"

	"github.com/pquerna/otp/totp"
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
	if !totpSecretEnc.Valid || totpSecretEnc.String == "" {
		return errors.New("2fa is misconfigured")
	}
	secret, err := helper.Decrypt(totpSecretEnc.String)
	if err != nil {
		return errors.New("2fa is misconfigured")
	}

	// Rate-limit + validate + reject replay, mirroring the login path so a step-up code is
	// single-use within its window.
	if limited, _ := registerTOTPAttempt(userID); limited {
		return errors.New("too many 2FA attempts, try again shortly")
	}
	if !totp.Validate(totpCode, secret) {
		return errors.New("invalid 2FA code")
	}
	if totpReplayed(userID, totpCode) {
		return errors.New("2FA code already used")
	}
	markTOTPUsed(userID, totpCode)
	clearTOTPAttempts(userID)
	return nil
}

// stepUp re-authenticates the caller for a sensitive action from the request-supplied password
// and TOTP code. On success it returns true. On ANY failure it writes a 428 (Precondition
// Required) response — never 401 — carrying {error, stepup:true, totp:<bool>}, so a wrong
// credential re-prompts in place instead of tripping the client's 401 auto-logout. The `totp`
// flag tells the UI whether to render an authenticator-code field.
func (s *Service) stepUp(w http.ResponseWriter, callerID int64, password, totpCode string) bool {
	err := s.VerifyStepUp(callerID, password, totpCode)
	if err == nil {
		return true
	}
	msg := err.Error()
	if errors.Is(err, ErrStepUpTOTPRequired) {
		msg = "two-factor authentication code required"
	}
	router.JSONWithStatus(w, map[string]interface{}{
		"error":  msg,
		"stepup": true,
		"totp":   s.TOTPEnabled(callerID),
	}, http.StatusPreconditionRequired)
	return false
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
