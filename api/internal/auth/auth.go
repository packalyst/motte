package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"api/internal/database"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/settings"
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
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	CreatedAt   time.Time `json:"createdAt"`
	LastLogin   time.Time `json:"lastLogin,omitempty"`
	Role        string    `json:"role"`
	ScopeKind   string    `json:"scopeKind,omitempty"`
	ScopeValues string    `json:"scopeValues,omitempty"`
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
		"Login":                 s.handleLogin,
		"Logout":                s.handleLogout,
		"GetCurrentUser":        s.handleGetCurrentUser,
		"CreateUser":            s.handleCreateUser,
		"ListUsers":             s.handleListUsers,
		"UpdateUserRole":        s.handleUpdateUserRole,
		"UpdateUserScope":       s.handleUpdateUserScope,
		"DeleteUser":            s.handleDeleteUser,
		"GetSessions":           s.handleGetSessions,
		"RevokeSession":         s.handleRevokeSession,
		"RevokeOtherSessions":   s.handleRevokeOtherSessions,
		"ChangePassword":        s.handleChangePassword,
		"Setup2FA":              s.handleSetup2FA,
		"Enable2FA":             s.handleEnable2FA,
		"Disable2FA":            s.handleDisable2FA,
		"Unlock":                s.handleUnlock,
		"Lock":                  s.handleLock,
		"PasskeyRegisterBegin":  s.handlePasskeyRegisterBegin,
		"PasskeyRegisterFinish": s.handlePasskeyRegisterFinish,
		"PasskeyLoginBegin":     s.handlePasskeyLoginBegin,
		"PasskeyLoginFinish":    s.handlePasskeyLoginFinish,
		"ListPasskeys":          s.handleListPasskeys,
		"DeletePasskey":         s.handleDeletePasskey,
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

// CreateUser creates a new user account with the given role. Scope defaults to all
// (unrestricted); callers assign a narrower scope afterwards with SetUserScope.
func (s *Service) CreateUser(username, password, role string) (*User, error) {
	// Validate input
	username = normalizeUsername(username)
	if len(username) < 3 {
		return nil, errors.New("username must be at least 3 characters")
	}
	if !ValidRole(role) {
		return nil, fmt.Errorf("invalid role %q", role)
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// Hash password
	hash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Insert user
	result, err := s.db.Exec(
		"INSERT INTO users (username, password_hash, role, scope_kind, scope_values) VALUES (?, ?, ?, 'all', '')",
		username, hash, role,
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
		Role:      role,
		ScopeKind: ScopeAll,
	}, nil
}

// Login validates credentials and creates a session
func (s *Service) Login(username, password, totpCode, ipAddress, userAgent string) (*LoginResponse, error) {
	username = normalizeUsername(username)

	// Get user including 2FA fields
	var user User
	var passwordHash string
	var lastLogin sql.NullTime
	var totpSecretEnc sql.NullString
	var totpEnabled int
	err := s.db.QueryRow(
		"SELECT id, username, password_hash, created_at, last_login, totp_secret_enc, COALESCE(totp_enabled, 0), role, scope_kind, scope_values FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &user.CreatedAt, &lastLogin, &totpSecretEnc, &totpEnabled, &user.Role, &user.ScopeKind, &user.ScopeValues)

	if err == sql.ErrNoRows {
		// Spend one Argon2id computation so the unknown-user path matches the timing of a
		// real verification (user-enumeration resistance).
		dummyVerify(password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %v", err)
	}
	user.LastLogin = database.TimeFromNull(lastLogin, time.Time{})

	// Verify password (Argon2id, or legacy bcrypt pending migration).
	passwordOK, needsRehash, _ := verifyPassword(password, passwordHash)
	if !passwordOK {
		return nil, ErrInvalidCredentials
	}

	// Check 2FA if enabled
	if totpEnabled == 1 {
		if totpCode == "" {
			return nil, ErrTOTPRequired
		}
		if err := verifyTOTP(user.ID, totpSecretEnc, totpCode); err != nil {
			return nil, err
		}
	}

	// Password verified and 2FA (if any) satisfied — migrate a legacy/weak hash to Argon2id.
	if needsRehash {
		s.upgradeHash(user.ID, password)
	}

	// Password verified and 2FA (if any) satisfied — issue a session.
	return s.createSession(user, ipAddress, userAgent)
}

// createSession issues a fresh session for an already-authenticated user and returns the login
// response. Shared by every primary auth path (password login, passkey login) so session creation,
// last-login bookkeeping and the new-device notification stay identical. Stores only the token hash.
func (s *Service) createSession(user User, ipAddress, userAgent string) (*LoginResponse, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	expiresAt := time.Now().Add(time.Duration(settings.SessionTimeoutHours()) * time.Hour)

	if _, err := s.db.Exec(
		"INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent, last_active) VALUES (?, ?, ?, ?, ?, ?)",
		hashToken(sessionID), user.ID, expiresAt, ipAddress, userAgent, time.Now(),
	); err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	s.db.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), user.ID)

	// New-login notification (async, don't block the response).
	go func() {
		loginNotifyMu.RLock()
		notifyFn := loginNotifyCallback
		loginNotifyMu.RUnlock()
		if notifyFn != nil {
			notifyFn(user.ID, ipAddress, helper.ParseUserAgent(userAgent), userAgent)
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
		SELECT s.id, s.user_id, s.expires_at, u.id, u.username, u.created_at, u.last_login, u.role, u.scope_kind, u.scope_values
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.id = ? AND s.expires_at > datetime('now')
	`, hashToken(token)).Scan(
		&session.ID, &session.UserID, &session.ExpiresAt,
		&user.ID, &user.Username, &user.CreatedAt, &lastLogin, &user.Role, &user.ScopeKind, &user.ScopeValues,
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
	`, hashToken(token))
}

// Logout invalidates a session
func (s *Service) Logout(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", hashToken(token))
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

// hashToken returns the storage key for a session token. The raw token is the bearer
// credential held only by the client; the database stores just this hash, so a DB read
// (backup leak, injection elsewhere) yields no usable tokens. sha256 is appropriate
// here: the token is already 256 bits of crypto/rand entropy, so no salt/KDF is needed.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
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

// auditName is the name a failed or blocked login is logged under: the typed username only when
// such a user exists, so a password pasted into the username field never lands in the audit log.
// normalizeUsername is how a username is stored and looked up: trimmed, lower case.
func normalizeUsername(s string) string { return strings.TrimSpace(strings.ToLower(s)) }

func (s *Service) auditName(typed string) string {
	name := normalizeUsername(typed)
	var one int
	if name != "" && s.db.QueryRow("SELECT 1 FROM users WHERE username = ?", name).Scan(&one) == nil {
		return name
	}
	return "(unknown user)"
}

// HTTP Handlers

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := helper.GetClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	var req LoginRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Rate limit: atomically check the lockout AND reserve this attempt's slot, so a burst
	// of concurrent attempts can't slip past a stale "under the limit" read. An IPv6 client
	// counts by its /64, so changing address doesn't buy more attempts.
	limitKey := helper.RateKey(clientIP)
	if err := loginLimiter.reserve(limitKey); err != nil {
		events.Audit("auth", "login_blocked", events.SeverityWarning,
			s.auditName(req.Username), clientIP,
			"Login temporarily blocked: too many failed attempts")
		tooManyAttempts(w, err)
		return
	}
	// And per account, from every client together: a guess spread over many addresses. Password
	// login only (passkey sign-in doesn't come here). A paused account costs this client nothing.
	account := accountKeyOf(req.Username)
	if err := accountLimiter.reserve(account); err != nil {
		loginLimiter.refund(limitKey)
		events.Audit("auth", "login_account_paused", events.SeverityWarning,
			s.auditName(req.Username), clientIP,
			"Password login to this account paused: too many failed attempts from all addresses (passkeys still work)")
		tooManyAttempts(w, err)
		return
	}

	resp, err := s.Login(req.Username, req.Password, req.TOTPCode, clientIP, userAgent)
	if err != nil {
		if err == ErrTOTPRequired {
			// Correct password, 2FA still pending — not a failed attempt, so give the slots back.
			loginLimiter.refund(limitKey)
			accountLimiter.refund(account)
			router.JSONError(w, "2FA code required", http.StatusPreconditionRequired)
			return
		}
		// Genuine failure — the slot was already counted by loginLimiter.reserve above.
		events.Audit("auth", "login_failed", events.SeverityWarning,
			s.auditName(req.Username), clientIP,
			fmt.Sprintf("Login failed: %s", err.Error()))
		if tooManyAttempts(w, err) {
			return
		}
		if err == ErrInvalidCredentials {
			router.JSONError(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		router.JSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Clear failed attempts on successful login (refunds the reserved slots).
	loginLimiter.clear(limitKey)
	accountLimiter.clear(account)

	events.Audit("auth", "login", events.SeverityInfo, resp.User.Username, clientIP,
		fmt.Sprintf("Login succeeded for %q", resp.User.Username))

	// Set the session as an HttpOnly, SameSite=Strict (Secure/__Host- over HTTPS) cookie so
	// the browser never exposes it to JavaScript. The raw token is still returned in the body
	// for non-browser API clients (Bearer); the UI ignores it and relies on the cookie.
	if exp, perr := time.Parse(time.RFC3339, resp.ExpiresAt); perr == nil {
		helper.SetSessionCookie(w, r, resp.Token, exp)
	}

	router.JSON(w, resp)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	if token != "" {
		// Resolve the session to attribute the audit entry before invalidating it.
		if u, err := s.ValidateSession(token); err == nil {
			events.Audit("auth", "logout", events.SeverityInfo, u.Username, helper.GetClientIP(r),
				fmt.Sprintf("Logout for %q", u.Username))
		}
		s.Logout(token)
	}
	helper.ClearSessionCookie(w, r)
	router.JSON(w, map[string]string{"message": "Logged out"})
}

func (s *Service) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
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

	// Embed the user's fields and add session-policy hints the UI needs: whether to collect a
	// 2FA code on step-up prompts, the idle-lock timeout (0 = disabled), and the display timezone.
	resp := struct {
		*User
		TOTPEnabled     bool   `json:"totpEnabled"`
		IdleLockMinutes int    `json:"idleLockMinutes"`
		Locked          bool   `json:"locked"`
		DisplayTimezone string `json:"displayTimezone"`
	}{
		User:            user,
		TOTPEnabled:     s.TOTPEnabled(user.ID),
		IdleLockMinutes: settings.IdleLockMinutes(),
		Locked:          s.IsSessionLocked(token),
		DisplayTimezone: settings.DisplayTimezone(),
	}
	router.JSON(w, resp)
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	// Creating another panel login is a sensitive, persistence-granting action, so it
	// requires STEP-UP re-authentication (the caller's current password) — a stolen
	// session token alone must not be able to mint a new user — and it is audit-logged.
	// The assigned role is owner-gated (canAssignRole); the route itself is admin+.
	token := helper.SessionToken(r)
	if token == "" {
		router.JSONError(w, "No token provided", http.StatusUnauthorized)
		return
	}
	caller, err := s.ValidateSession(token)
	if err != nil {
		router.JSONError(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	var req struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		Role            string `json:"role"`
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if !s.StepUp(w, caller.ID, req.CurrentPassword, req.TotpCode) {
		return
	}

	role := req.Role
	if role == "" {
		role = RoleViewer // least privilege by default
	}
	if !ValidRole(role) {
		router.JSONError(w, "invalid role", http.StatusBadRequest)
		return
	}
	if err := s.canAssignRole(caller, role); err != nil {
		router.JSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	user, err := s.CreateUser(req.Username, req.Password, role)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	events.Audit("auth", "user_created", events.SeverityWarning, caller.Username, helper.GetClientIP(r),
		fmt.Sprintf("Panel user %q (role %s) created by %q", user.Username, role, caller.Username))
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
