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

// registerLoginAttempt ATOMICALLY checks the lockout and reserves an attempt slot in a
// single critical section, closing the check-then-increment race where a burst of
// concurrent requests could all pass a stale "under the limit" read before any of them
// incremented. Every attempt consumes a slot up front; a success (clearLoginAttempts) or a
// correct-password-but-2FA-pending result (refundLoginAttempt) gives it back. Returns
// whether the caller is locked out and, if so, the remaining lockout time.
func registerLoginAttempt(ip string) (bool, time.Duration) {
	loginAttemptsMutex.Lock()
	defer loginAttemptsMutex.Unlock()

	now := time.Now()
	attempt, exists := loginAttempts[ip]
	if !exists {
		loginAttempts[ip] = &loginAttempt{count: 1, firstTry: now}
		return false, 0
	}

	// Currently locked out?
	if !attempt.lockedAt.IsZero() {
		if remaining := loginLockoutTime - now.Sub(attempt.lockedAt); remaining > 0 {
			return true, remaining
		}
		// Lockout expired — reset and count this as the first attempt of a new window.
		attempt.count = 1
		attempt.firstTry = now
		attempt.lockedAt = time.Time{}
		return false, 0
	}

	// Counting window expired — reset.
	if now.Sub(attempt.firstTry) > loginLockoutWindow {
		attempt.count = 1
		attempt.firstTry = now
		return false, 0
	}

	// Reserve this attempt; lock once we exceed the allowance.
	attempt.count++
	if attempt.count > maxLoginAttempts {
		attempt.lockedAt = now
		log.Printf("Login rate limit: IP %s locked out after %d attempts", ip, attempt.count)
		return true, loginLockoutTime
	}
	return false, 0
}

// refundLoginAttempt returns a slot reserved by registerLoginAttempt when the attempt was
// not actually a failure (correct password, but 2FA still pending). No-op once locked.
func refundLoginAttempt(ip string) {
	loginAttemptsMutex.Lock()
	defer loginAttemptsMutex.Unlock()
	if a, ok := loginAttempts[ip]; ok && a.lockedAt.IsZero() && a.count > 0 {
		a.count--
		if a.count == 0 {
			delete(loginAttempts, ip)
		}
	}
}

// clearLoginAttempts clears failed attempts for an IP after successful login
func clearLoginAttempts(ip string) {
	loginAttemptsMutex.Lock()
	delete(loginAttempts, ip)
	loginAttemptsMutex.Unlock()
}

// registerTOTPAttempt atomically checks the lockout and reserves a TOTP attempt slot in one
// critical section (same race-free pattern as registerLoginAttempt, keyed by user ID). It
// is called just before verifying a code; a successful verify refunds via clearTOTPAttempts.
func registerTOTPAttempt(userID int64) (bool, time.Duration) {
	totpAttemptsMutex.Lock()
	defer totpAttemptsMutex.Unlock()

	now := time.Now()
	attempt, exists := totpAttempts[userID]
	if !exists {
		totpAttempts[userID] = &loginAttempt{count: 1, firstTry: now}
		return false, 0
	}

	if !attempt.lockedAt.IsZero() {
		if remaining := loginLockoutTime - now.Sub(attempt.lockedAt); remaining > 0 {
			return true, remaining
		}
		attempt.count = 1
		attempt.firstTry = now
		attempt.lockedAt = time.Time{}
		return false, 0
	}

	if now.Sub(attempt.firstTry) > loginLockoutWindow {
		attempt.count = 1
		attempt.firstTry = now
		return false, 0
	}

	attempt.count++
	if attempt.count > maxTOTPAttempts {
		attempt.lockedAt = now
		log.Printf("TOTP rate limit: user ID %d locked out after %d attempts", userID, attempt.count)
		return true, loginLockoutTime
	}
	return false, 0
}

// clearTOTPAttempts clears failed TOTP attempts for a user after success
func clearTOTPAttempts(userID int64) {
	totpAttemptsMutex.Lock()
	delete(totpAttempts, userID)
	totpAttemptsMutex.Unlock()
}
