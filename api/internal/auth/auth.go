package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/settings"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// LoginNotifyFunc is called after successful login (for push notifications)
type LoginNotifyFunc func(userID int64, ipAddress, deviceName, userAgent string)

var (
	loginNotifyCallback LoginNotifyFunc
	loginNotifyMu       sync.RWMutex
)

// SetLoginNotifyCallback sets the callback for login notifications (called by PWA service)
func SetLoginNotifyCallback(fn LoginNotifyFunc) {
	loginNotifyMu.Lock()
	defer loginNotifyMu.Unlock()
	loginNotifyCallback = fn
}

// Error types
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidSession     = errors.New("invalid or expired session")
	ErrTOTPRequired       = errors.New("2FA code required")
)

// Service handles authentication
type Service struct {
	db *database.DB
}

// User represents a user account
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
	LastLogin time.Time `json:"lastLogin,omitempty"`
}

// Session represents a login session
type Session struct {
	ID         string    `json:"id"`
	UserID     int64     `json:"userId"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	IPAddress  string    `json:"ipAddress,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
	LastActive time.Time `json:"lastActive,omitempty"`
	Current    bool      `json:"current,omitempty"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totpCode,omitempty"`
}

// LoginResponse represents successful login response
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	User      User   `json:"user"`
}

// New creates a new auth service
func New() (*Service, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}

	svc := &Service{
		db: db,
	}

	log.Printf("Auth service initialized")
	return svc, nil
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"Login":               s.handleLogin,
		"Logout":              s.handleLogout,
		"GetCurrentUser":      s.handleGetCurrentUser,
		"CreateUser":          s.handleCreateUser,
		"GetSessions":         s.handleGetSessions,
		"RevokeSession":       s.handleRevokeSession,
		"RevokeOtherSessions": s.handleRevokeOtherSessions,
		"ChangePassword":      s.handleChangePassword,
		"Get2FAStatus":        s.handleGet2FAStatus,
		"Setup2FA":            s.handleSetup2FA,
		"Enable2FA":           s.handleEnable2FA,
		"Disable2FA":          s.handleDisable2FA,
	}
}

// validatePassword checks password strength
// Requires: 8+ chars, uppercase, lowercase, number, special char
func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsNumber(c):
			hasNumber = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// CreateUser creates a new user account
func (s *Service) CreateUser(username, password string) (*User, error) {
	// Validate input
	username = strings.TrimSpace(strings.ToLower(username))
	if len(username) < 3 {
		return nil, errors.New("username must be at least 3 characters")
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Insert user
	result, err := s.db.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, string(hash),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return nil, ErrUserExists
		}
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	id, _ := result.LastInsertId()
	return &User{
		ID:        id,
		Username:  username,
		CreatedAt: time.Now(),
	}, nil
}

// Login validates credentials and creates a session
func (s *Service) Login(username, password, totpCode, ipAddress, userAgent string) (*LoginResponse, error) {
	username = strings.TrimSpace(strings.ToLower(username))

	// Get user including 2FA fields
	var user User
	var passwordHash string
	var lastLogin sql.NullTime
	var totpSecretEnc sql.NullString
	var totpEnabled int
	err := s.db.QueryRow(
		"SELECT id, username, password_hash, created_at, last_login, totp_secret_enc, COALESCE(totp_enabled, 0) FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &user.CreatedAt, &lastLogin, &totpSecretEnc, &totpEnabled)

	if err == sql.ErrNoRows {
		// Perform dummy bcrypt comparison to prevent timing attacks
		bcrypt.CompareHashAndPassword([]byte("$2a$10$dummyhashtopreventtimingattacks"), []byte(password))
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %v", err)
	}
	user.LastLogin = database.TimeFromNull(lastLogin, time.Time{})

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Check 2FA if enabled
	if totpEnabled == 1 {
		if totpCode == "" {
			return nil, ErrTOTPRequired
		}

		// Check TOTP rate limit
		if limited, remaining := checkTOTPRateLimit(user.ID); limited {
			return nil, fmt.Errorf("too many failed 2FA attempts, try again in %d seconds", int(remaining.Seconds()))
		}

		// Decrypt and verify TOTP code
		if totpSecretEnc.Valid && totpSecretEnc.String != "" {
			secret, err := helper.Decrypt(totpSecretEnc.String)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt 2FA secret: %v", err)
			}

			if !totp.Validate(totpCode, secret) {
				recordFailedTOTP(user.ID)
				return nil, errors.New("invalid 2FA code")
			}

			// Clear TOTP attempts on success
			clearTOTPAttempts(user.ID)
		}
	}

	// Create session with IP and user agent
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionHours := settings.GetSettingInt("session_timeout", 24)
	expiresAt := time.Now().Add(time.Duration(sessionHours) * time.Hour)

	_, err = s.db.Exec(
		"INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent, last_active) VALUES (?, ?, ?, ?, ?, ?)",
		sessionID, user.ID, expiresAt, ipAddress, userAgent, time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	// Update last login
	s.db.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), user.ID)

	// Send push notification for new login (async, don't block login)
	go func() {
		loginNotifyMu.RLock()
		notifyFn := loginNotifyCallback
		loginNotifyMu.RUnlock()
		if notifyFn != nil {
			deviceName := helper.ParseUserAgent(userAgent)
			notifyFn(user.ID, ipAddress, deviceName, userAgent)
		}
	}()

	return &LoginResponse{
		Token:     sessionID,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		User:      user,
	}, nil
}

// ValidateSession checks if a session token is valid
func (s *Service) ValidateSession(token string) (*User, error) {
	var session Session
	var user User
	var lastLogin sql.NullTime

	err := s.db.QueryRow(`
		SELECT s.id, s.user_id, s.expires_at, u.id, u.username, u.created_at, u.last_login
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.id = ? AND s.expires_at > datetime('now')
	`, token).Scan(
		&session.ID, &session.UserID, &session.ExpiresAt,
		&user.ID, &user.Username, &user.CreatedAt, &lastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate session: %v", err)
	}
	user.LastLogin = database.TimeFromNull(lastLogin, time.Time{})

	// Update session activity (only if > 1 minute since last update)
	go s.updateSessionActivity(token)

	return &user, nil
}

// updateSessionActivity updates last_active timestamp (runs async)
func (s *Service) updateSessionActivity(token string) {
	s.db.Exec(`
		UPDATE sessions
		SET last_active = datetime('now')
		WHERE id = ? AND (last_active IS NULL OR last_active < datetime('now', '-1 minute'))
	`, token)
}

// Logout invalidates a session
func (s *Service) Logout(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", token)
	return err
}

// HasUsers checks if any users exist
func (s *Service) HasUsers() bool {
	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count > 0
}

// generateSessionID generates a random session ID
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// parseTime tries multiple time formats for SQLite compatibility
func parseTime(s string) time.Time {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999+00:00",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// HTTP Handlers

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := helper.GetClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Check rate limit
	if locked, remaining := checkLoginRateLimit(clientIP); locked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(remaining.Seconds())))
		router.JSONError(w, fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", int(remaining.Seconds())), http.StatusTooManyRequests)
		return
	}

	var req LoginRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	resp, err := s.Login(req.Username, req.Password, req.TOTPCode, clientIP, userAgent)
	if err != nil {
		// Record failed attempt (except for TOTP required which isn't a failure)
		if err != ErrTOTPRequired {
			if recordFailedLogin(clientIP) {
				router.JSONError(w, "Account locked due to too many failed attempts", http.StatusTooManyRequests)
				return
			}
		}

		if err == ErrTOTPRequired {
			router.JSONError(w, "2FA code required", http.StatusPreconditionRequired)
			return
		}
		if err == ErrInvalidCredentials {
			router.JSONError(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		router.JSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Clear failed attempts on successful login
	clearLoginAttempts(clientIP)

	router.JSON(w, resp)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token != "" {
		s.Logout(token)
	}
	router.JSON(w, map[string]string{"message": "Logged out"})
}

func (s *Service) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
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

	router.JSON(w, user)
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	user, err := s.CreateUser(req.Username, req.Password)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	router.JSON(w, user)
}

// Service instance management
var serviceInstance *Service

// GetService returns the auth service instance for use by other packages
func GetService() *Service {
	return serviceInstance
}

// SetService sets the auth service instance
func SetService(svc *Service) {
	serviceInstance = svc
}
