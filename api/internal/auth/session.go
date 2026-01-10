package auth

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"api/internal/helper"
	"api/internal/router"

	"golang.org/x/crypto/bcrypt"
)

// ChangePasswordRequest for password change
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// GetSessions returns all active sessions for a user
func (s *Service) GetSessions(userID int64, currentToken string) ([]Session, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, created_at, expires_at, COALESCE(ip_address, ''), COALESCE(user_agent, ''), COALESCE(last_active, created_at)
		FROM sessions
		WHERE user_id = ? AND expires_at > datetime('now')
		ORDER BY last_active DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %v", err)
	}
	defer rows.Close()

	sessions := []Session{} // Initialize as empty slice, not nil
	for rows.Next() {
		var sess Session
		var createdAt, expiresAt, lastActive string
		if err := rows.Scan(&sess.ID, &sess.UserID, &createdAt, &expiresAt, &sess.IPAddress, &sess.UserAgent, &lastActive); err != nil {
			log.Printf("Error scanning session: %v", err)
			continue
		}
		// Parse times - try multiple formats (SQLite stores in various formats)
		sess.CreatedAt = parseTime(createdAt)
		sess.ExpiresAt = parseTime(expiresAt)
		sess.LastActive = parseTime(lastActive)
		sess.Current = sess.ID == currentToken
		sessions = append(sessions, sess)
	}

	return sessions, nil
}

// RevokeSession invalidates a specific session
func (s *Service) RevokeSession(sessionID string, userID int64) error {
	result, err := s.db.Exec("DELETE FROM sessions WHERE id = ? AND user_id = ?", sessionID, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %v", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return errors.New("session not found")
	}
	return nil
}

// RevokeOtherSessions revokes all sessions except the current one
func (s *Service) RevokeOtherSessions(currentToken string, userID int64) (int64, error) {
	result, err := s.db.Exec("DELETE FROM sessions WHERE user_id = ? AND id != ?", userID, currentToken)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke sessions: %v", err)
	}
	return result.RowsAffected()
}

// ChangePassword changes the user's password after verifying the current one
func (s *Service) ChangePassword(userID int64, currentPassword, newPassword string) error {
	// Get current password hash
	var passwordHash string
	err := s.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&passwordHash)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Verify current password FIRST (before any other validation)
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(currentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}

	// Only after verifying current password, check if new password is different
	if currentPassword == newPassword {
		return errors.New("new password must be different from current password")
	}

	// Validate new password strength
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Update password
	_, err = s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(newHash), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %v", err)
	}

	return nil
}

// HTTP Handlers for session management

func (s *Service) handleGetSessions(w http.ResponseWriter, r *http.Request) {
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

	sessions, err := s.GetSessions(user.ID, token)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]interface{}{"sessions": sessions})
}

func (s *Service) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
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

	// Extract session ID from URL path: /api/auth/sessions/{id}/revoke
	path := strings.TrimPrefix(r.URL.Path, "/api/auth/sessions/")
	sessionID := strings.TrimSuffix(path, "/revoke")
	if sessionID == "" || sessionID == path {
		router.JSONError(w, "Session ID required", http.StatusBadRequest)
		return
	}

	// Don't allow revoking current session
	if sessionID == token {
		router.JSONError(w, "Cannot revoke current session. Use logout instead.", http.StatusBadRequest)
		return
	}

	if err := s.RevokeSession(sessionID, user.ID); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]string{"message": "Session revoked"})
}

func (s *Service) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
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

	count, err := s.RevokeOtherSessions(token, user.ID)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]interface{}{
		"message": fmt.Sprintf("Revoked %d sessions", count),
		"count":   count,
	})
}

func (s *Service) handleChangePassword(w http.ResponseWriter, r *http.Request) {
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

	var req ChangePasswordRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if err := s.ChangePassword(user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		// Check if it's a validation error
		if strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "incorrect") {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.Contains(err.Error(), "incorrect") {
			router.JSONError(w, err.Error(), http.StatusUnauthorized)
			return
		}
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]string{"message": "Password changed successfully"})
}
