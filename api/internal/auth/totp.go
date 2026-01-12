package auth

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"image/png"
	"log"
	"net/http"

	"api/internal/helper"
	"api/internal/router"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// Enable2FARequest for enabling 2FA
type Enable2FARequest struct {
	Code string `json:"code"`
}

// Disable2FARequest for disabling 2FA
type Disable2FARequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// handleGet2FAStatus returns the 2FA status for current user
func (s *Service) handleGet2FAStatus(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		router.JSONError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		router.JSONError(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	var totpEnabled int
	err = s.db.QueryRow("SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?", user.ID).Scan(&totpEnabled)
	if err != nil {
		router.JSONError(w, "Failed to get 2FA status", http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]bool{"enabled": totpEnabled == 1})
}

// handleSetup2FA generates a new TOTP secret and returns QR code
func (s *Service) handleSetup2FA(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
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
	token := helper.ExtractBearerToken(r)
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

	// Decrypt the secret
	secret, err := helper.Decrypt(totpSecretEnc.String)
	if err != nil {
		router.JSONError(w, "Failed to decrypt secret", http.StatusInternalServerError)
		return
	}

	// Check TOTP rate limit
	if limited, remaining := checkTOTPRateLimit(user.ID); limited {
		router.JSONError(w, fmt.Sprintf("Too many failed attempts. Try again in %d seconds", int(remaining.Seconds())), http.StatusTooManyRequests)
		return
	}

	// Verify the code
	if !totp.Validate(req.Code, secret) {
		recordFailedTOTP(user.ID)
		router.JSONError(w, "Invalid verification code", http.StatusBadRequest)
		return
	}

	// Clear TOTP attempts on success
	clearTOTPAttempts(user.ID)

	// Enable 2FA
	_, err = s.db.Exec("UPDATE users SET totp_enabled = 1 WHERE id = ?", user.ID)
	if err != nil {
		router.JSONError(w, "Failed to enable 2FA", http.StatusInternalServerError)
		return
	}

	log.Printf("2FA enabled for user %s", user.Username)
	router.JSON(w, map[string]string{"message": "2FA enabled successfully"})
}

// handleDisable2FA disables 2FA after verifying password and TOTP code
func (s *Service) handleDisable2FA(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
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

	// Get password hash and 2FA secret
	var passwordHash string
	var totpSecretEnc sql.NullString
	var totpEnabled int
	err = s.db.QueryRow("SELECT password_hash, totp_secret_enc, COALESCE(totp_enabled, 0) FROM users WHERE id = ?", user.ID).Scan(&passwordHash, &totpSecretEnc, &totpEnabled)
	if err != nil {
		router.JSONError(w, "User not found", http.StatusInternalServerError)
		return
	}

	if totpEnabled != 1 {
		router.JSONError(w, "2FA is not enabled", http.StatusBadRequest)
		return
	}

	// Verify password first
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		router.JSONError(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Check TOTP rate limit
	if limited, remaining := checkTOTPRateLimit(user.ID); limited {
		router.JSONError(w, fmt.Sprintf("Too many failed attempts. Try again in %d seconds", int(remaining.Seconds())), http.StatusTooManyRequests)
		return
	}

	// Decrypt and verify TOTP code
	if totpSecretEnc.Valid && totpSecretEnc.String != "" {
		secret, err := helper.Decrypt(totpSecretEnc.String)
		if err != nil {
			router.JSONError(w, "Failed to decrypt secret", http.StatusInternalServerError)
			return
		}

		if !totp.Validate(req.Code, secret) {
			recordFailedTOTP(user.ID)
			router.JSONError(w, "Invalid 2FA code", http.StatusBadRequest)
			return
		}
	}

	// Clear TOTP attempts on success
	clearTOTPAttempts(user.ID)

	// Disable 2FA and clear secret
	_, err = s.db.Exec("UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL WHERE id = ?", user.ID)
	if err != nil {
		router.JSONError(w, "Failed to disable 2FA", http.StatusInternalServerError)
		return
	}

	log.Printf("2FA disabled for user %s", user.Username)
	router.JSON(w, map[string]string{"message": "2FA disabled successfully"})
}
