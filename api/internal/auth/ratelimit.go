package auth

import (
	"crypto/subtle"
	"log"
	"sync"
	"time"

	"api/internal/helper"
)

// Rate limiting for login attempts
const (
	maxLoginAttempts = 5 // Max failed attempts before lockout
	maxTOTPAttempts  = 5 // Max failed TOTP attempts before lockout
)

// Use helper constants for lockout timing
var (
	loginLockoutWindow = helper.LoginLockoutWindow   // Window for counting attempts
	loginLockoutTime   = helper.LoginLockoutDuration // How long to lock out after max attempts
)

type loginAttempt struct {
	count    int
	firstTry time.Time
	lockedAt time.Time
}

var (
	loginAttempts      = make(map[string]*loginAttempt)
	loginAttemptsMutex sync.RWMutex

	// TOTP rate limiting (keyed by user ID)
	totpAttempts      = make(map[int64]*loginAttempt)
	totpAttemptsMutex sync.RWMutex

	// Last successfully-used TOTP code per user, to block replay of a captured code
	// within its validity window. Keyed by user ID, so bounded by the user count.
	usedTOTP      = make(map[int64]usedTOTPCode)
	usedTOTPMutex sync.Mutex
)

// usedTOTPCode records a consumed code and when the replay guard for it expires.
type usedTOTPCode struct {
	code    string
	expires time.Time
}

// totpReplayed reports whether code was already consumed by this user within its window.
func totpReplayed(userID int64, code string) bool {
	usedTOTPMutex.Lock()
	defer usedTOTPMutex.Unlock()
	u, ok := usedTOTP[userID]
	if !ok || time.Now().After(u.expires) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(u.code), []byte(code)) == 1
}

// markTOTPUsed records a successfully-used code so it can't be replayed. The window
// (90s) covers the TOTP period plus the library's ±1 step validation skew.
func markTOTPUsed(userID int64, code string) {
	usedTOTPMutex.Lock()
	defer usedTOTPMutex.Unlock()
	usedTOTP[userID] = usedTOTPCode{code: code, expires: time.Now().Add(90 * time.Second)}
}

func init() {
	// Initialize trusted proxies from environment
	helper.InitTrustedProxies(helper.GetEnvOptional("TRUSTED_PROXIES", ""))

	// Cleanup stale login attempts to prevent unbounded memory growth
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			now := time.Now()

			// Cleanup login attempts
			loginAttemptsMutex.Lock()
			for ip, attempt := range loginAttempts {
				// Remove if lockout expired
				if !attempt.lockedAt.IsZero() && now.Sub(attempt.lockedAt) > loginLockoutTime {
					delete(loginAttempts, ip)
					continue
				}
				// Remove if window expired and not locked
				if attempt.lockedAt.IsZero() && now.Sub(attempt.firstTry) > loginLockoutWindow {
					delete(loginAttempts, ip)
				}
			}
			loginAttemptsMutex.Unlock()

			// Cleanup TOTP attempts
			totpAttemptsMutex.Lock()
			for userID, attempt := range totpAttempts {
				if !attempt.lockedAt.IsZero() && now.Sub(attempt.lockedAt) > loginLockoutTime {
					delete(totpAttempts, userID)
					continue
				}
				if attempt.lockedAt.IsZero() && now.Sub(attempt.firstTry) > loginLockoutWindow {
					delete(totpAttempts, userID)
				}
			}
			totpAttemptsMutex.Unlock()

			// Cleanup expired TOTP replay-guard entries
			usedTOTPMutex.Lock()
			for userID, u := range usedTOTP {
				if now.After(u.expires) {
					delete(usedTOTP, userID)
				}
			}
			usedTOTPMutex.Unlock()
		}
	}()
}

// checkLoginRateLimit returns true if the IP is rate limited
func checkLoginRateLimit(ip string) (bool, time.Duration) {
	loginAttemptsMutex.RLock()
	attempt, exists := loginAttempts[ip]
	loginAttemptsMutex.RUnlock()

	if !exists {
		return false, 0
	}

	now := time.Now()

	// Check if currently locked out
	if !attempt.lockedAt.IsZero() {
		remaining := loginLockoutTime - now.Sub(attempt.lockedAt)
		if remaining > 0 {
			return true, remaining
		}
		// Lockout expired, reset
		loginAttemptsMutex.Lock()
		delete(loginAttempts, ip)
		loginAttemptsMutex.Unlock()
		return false, 0
	}

	// Check if window has expired (reset counter)
	if now.Sub(attempt.firstTry) > loginLockoutWindow {
		loginAttemptsMutex.Lock()
		delete(loginAttempts, ip)
		loginAttemptsMutex.Unlock()
		return false, 0
	}

	return false, 0
}

// recordFailedLogin records a failed login attempt and returns true if now locked out
func recordFailedLogin(ip string) bool {
	loginAttemptsMutex.Lock()
	defer loginAttemptsMutex.Unlock()

	now := time.Now()
	attempt, exists := loginAttempts[ip]

	if !exists {
		loginAttempts[ip] = &loginAttempt{
			count:    1,
			firstTry: now,
		}
		return false
	}

	// Reset if window expired
	if now.Sub(attempt.firstTry) > loginLockoutWindow {
		attempt.count = 1
		attempt.firstTry = now
		attempt.lockedAt = time.Time{}
		return false
	}

	attempt.count++
	if attempt.count >= maxLoginAttempts {
		attempt.lockedAt = now
		log.Printf("Login rate limit: IP %s locked out after %d failed attempts", ip, attempt.count)
		return true
	}

	return false
}

// clearLoginAttempts clears failed attempts for an IP after successful login
func clearLoginAttempts(ip string) {
	loginAttemptsMutex.Lock()
	delete(loginAttempts, ip)
	loginAttemptsMutex.Unlock()
}

// checkTOTPRateLimit returns true if the user is rate limited for TOTP attempts
func checkTOTPRateLimit(userID int64) (bool, time.Duration) {
	totpAttemptsMutex.RLock()
	attempt, exists := totpAttempts[userID]
	totpAttemptsMutex.RUnlock()

	if !exists {
		return false, 0
	}

	now := time.Now()

	// Check if currently locked out
	if !attempt.lockedAt.IsZero() {
		remaining := loginLockoutTime - now.Sub(attempt.lockedAt)
		if remaining > 0 {
			return true, remaining
		}
		// Lockout expired, reset
		totpAttemptsMutex.Lock()
		delete(totpAttempts, userID)
		totpAttemptsMutex.Unlock()
		return false, 0
	}

	// Check if window has expired (reset counter)
	if now.Sub(attempt.firstTry) > loginLockoutWindow {
		totpAttemptsMutex.Lock()
		delete(totpAttempts, userID)
		totpAttemptsMutex.Unlock()
		return false, 0
	}

	return false, 0
}

// recordFailedTOTP records a failed TOTP attempt and returns true if now locked out
func recordFailedTOTP(userID int64) bool {
	totpAttemptsMutex.Lock()
	defer totpAttemptsMutex.Unlock()

	now := time.Now()
	attempt, exists := totpAttempts[userID]

	if !exists {
		totpAttempts[userID] = &loginAttempt{
			count:    1,
			firstTry: now,
		}
		return false
	}

	// Reset if window expired
	if now.Sub(attempt.firstTry) > loginLockoutWindow {
		attempt.count = 1
		attempt.firstTry = now
		attempt.lockedAt = time.Time{}
		return false
	}

	attempt.count++
	if attempt.count >= maxTOTPAttempts {
		attempt.lockedAt = now
		log.Printf("TOTP rate limit: user ID %d locked out after %d failed attempts", userID, attempt.count)
		return true
	}

	return false
}

// clearTOTPAttempts clears failed TOTP attempts for a user after success
func clearTOTPAttempts(userID int64) {
	totpAttemptsMutex.Lock()
	delete(totpAttempts, userID)
	totpAttemptsMutex.Unlock()
}
