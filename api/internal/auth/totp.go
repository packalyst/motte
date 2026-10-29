package auth

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"log"
	"net/http"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"

	"github.com/pquerna/otp/totp"
)

// Enable2FARequest for enabling 2FA
type Enable2FARequest struct {
	Code string `json:"code"`
}

// errTOTPMisconfigured: 2FA is on but its secret is missing or unreadable. Never skip the code.
var errTOTPMisconfigured = errors.New("2FA is misconfigured for this account; contact an administrator")

// Disable2FARequest for disabling 2FA
type Disable2FARequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// handleSetup2FA generates a new TOTP secret and returns QR code
func (s *Service) handleSetup2FA(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	if token == "" {
		router.JSONError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		router.JSONError(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	// Check if 2FA is already enabled
	var totpEnabled int
	err = s.db.QueryRow("SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?", user.ID).Scan(&totpEnabled)
	if err != nil {
		router.JSONError(w, "Failed to get 2FA status", http.StatusInternalServerError)
		return
	}
	if totpEnabled == 1 {
		router.JSONError(w, "2FA is already enabled", http.StatusBadRequest)
		return
	}

	// Step-up (password) before provisioning 2FA: otherwise a stolen session could bind the
	// attacker's authenticator and lock the real owner out (disable needs password+code).
	var creds struct {
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&creds)
	if !s.StepUp(w, user.ID, creds.CurrentPassword, creds.TotpCode) {
		return
	}

	// Generate new TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      helper.TOTPIssuer,
		AccountName: user.Username,
	})
	if err != nil {
		router.JSONError(w, "Failed to generate 2FA secret", http.StatusInternalServerError)
		return
	}

	// Encrypt and store the secret temporarily (not enabled yet)
	encSecret, err := helper.Encrypt(key.Secret())
	if err != nil {
		router.JSONError(w, "Failed to encrypt secret", http.StatusInternalServerError)
		return
	}

	// Store secret but keep totp_enabled = 0 until verified
	_, err = s.db.Exec("UPDATE users SET totp_secret_enc = ? WHERE id = ?", encSecret, user.ID)
	if err != nil {
		router.JSONError(w, "Failed to save 2FA secret", http.StatusInternalServerError)
		return
	}

	// Generate QR code as base64 PNG
	img, err := key.Image(200, 200)
	if err != nil {
		router.JSONError(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		router.JSONError(w, "Failed to encode QR code", http.StatusInternalServerError)
		return
	}

	qrBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	router.JSON(w, map[string]string{
		"secret":  key.Secret(),
		"qrCode":  "data:image/png;base64," + qrBase64,
		"issuer":  helper.TOTPIssuer,
		"account": user.Username,
	})
}

// handleEnable2FA verifies the TOTP code and enables 2FA
func (s *Service) handleEnable2FA(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	if token == "" {
		router.JSONError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		router.JSONError(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	var req Enable2FARequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Code == "" {
		router.JSONError(w, "Verification code required", http.StatusBadRequest)
		return
	}

	// Get the stored (but not yet enabled) secret
	var totpSecretEnc sql.NullString
	var totpEnabled int
	err = s.db.QueryRow("SELECT totp_secret_enc, COALESCE(totp_enabled, 0) FROM users WHERE id = ?", user.ID).Scan(&totpSecretEnc, &totpEnabled)
	if err != nil {
		router.JSONError(w, "Failed to get 2FA status", http.StatusInternalServerError)
		return
	}

	if totpEnabled == 1 {
		router.JSONError(w, "2FA is already enabled", http.StatusBadRequest)
		return
	}

	if !totpSecretEnc.Valid || totpSecretEnc.String == "" {
		router.JSONError(w, "2FA setup not started. Call setup endpoint first.", http.StatusBadRequest)
		return
	}

	if err := verifyTOTP(user.ID, totpSecretEnc, req.Code); err != nil {
		if !tooManyAttempts(w, err) {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	// Enable 2FA
	_, err = s.db.Exec("UPDATE users SET totp_enabled = 1 WHERE id = ?", user.ID)
	if err != nil {
		router.JSONError(w, "Failed to enable 2FA", http.StatusInternalServerError)
		return
	}

	log.Printf("2FA enabled for user %s", user.Username)
	events.Audit("auth", "2fa_enabled", events.SeverityInfo, user.Username, helper.GetClientIP(r),
		fmt.Sprintf("2FA enabled for %q", user.Username))
	router.JSON(w, map[string]string{"message": "2FA enabled successfully"})
}

// handleDisable2FA disables 2FA after verifying password and TOTP code
func (s *Service) handleDisable2FA(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	if token == "" {
		router.JSONError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		router.JSONError(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	var req Disable2FARequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Password == "" {
		router.JSONError(w, "Password required", http.StatusBadRequest)
		return
	}

	if req.Code == "" {
		router.JSONError(w, "2FA code required", http.StatusBadRequest)
		return
	}

	if !s.TOTPEnabled(user.ID) {
		router.JSONError(w, "2FA is not enabled", http.StatusBadRequest)
		return
	}
	// Password and code go through step-up: both rate-limited, the code single-use, and a
	// missing secret fails closed.
	if !s.StepUp(w, user.ID, req.Password, req.Code) {
		return
	}

	// Disable 2FA and clear secret
	_, err = s.db.Exec("UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL WHERE id = ?", user.ID)
	if err != nil {
		router.JSONError(w, "Failed to disable 2FA", http.StatusInternalServerError)
		return
	}

	log.Printf("2FA disabled for user %s", user.Username)
	events.Audit("auth", "2fa_disabled", events.SeverityWarning, user.Username, helper.GetClientIP(r),
		fmt.Sprintf("2FA disabled for %q", user.Username))
	router.JSON(w, map[string]string{"message": "2FA disabled successfully"})
}

// verifyTOTP checks a 2FA code against the user's stored secret: rate-limited per user, single-use
// within its window, and fail-closed when the secret is missing. Shared by login, step-up (so
// unlock and turning 2FA off too) and turning 2FA on.
func verifyTOTP(userID int64, secretEnc sql.NullString, code string) error {
	if !secretEnc.Valid || secretEnc.String == "" {
		return errTOTPMisconfigured
	}
	secret, err := helper.Decrypt(secretEnc.String)
	if err != nil {
		return errTOTPMisconfigured
	}
	if err := totpLimiter.reserve(userID); err != nil {
		return err
	}
	if !totp.Validate(code, secret) {
		return errors.New("invalid 2FA code")
	}
	if err := claimTOTPCode(userID, code); err != nil {
		return err
	}
	totpLimiter.clear(userID)
	return nil
}
