package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// Every auth limit lives here: failed-attempt lockouts (login per IP, 2FA codes and password
// re-checks per user), how many passkey sign-ins may wait for an answer, and how many Argon2id
// computations run at once.
const (
	maxLoginAttempts    = 5 // failed logins per IP before lockout
	maxTOTPAttempts     = 5 // failed 2FA codes per user before lockout
	maxPasswordAttempts = 5 // wrong passwords per user at step-up, unlock and password change

	maxPendingPasskeyLogins      = 1000 // passkey sign-ins waiting for an answer, in total
	maxPendingPasskeyLoginsPerIP = 5    // ... and from one IP

	// maxConcurrentArgon2 caps simultaneous Argon2id computations: each takes argonMemoryKiB
	// (64 MiB), so a burst of logins or password checks queues instead of exhausting memory.
	maxConcurrentArgon2 = 4
)

// Use helper constants for lockout timing
var (
	loginLockoutWindow = helper.LoginLockoutWindow   // Window for counting attempts
	loginLockoutTime   = helper.LoginLockoutDuration // How long to lock out after max attempts
)

var (
	loginLimiter    = newAttemptLimiter[string]("Login", maxLoginAttempts)
	totpLimiter     = newAttemptLimiter[int64]("2FA", maxTOTPAttempts)
	passwordLimiter = newAttemptLimiter[int64]("Password", maxPasswordAttempts)
)

// tooManyAttemptsError is returned while a key is locked out; handlers answer 429.
type tooManyAttemptsError struct {
	what  string
	retry time.Duration
}

func (e *tooManyAttemptsError) Error() string {
	return fmt.Sprintf("too many failed %s attempts, try again in %d seconds", e.what, int(e.retry.Seconds()))
}

// tooManyAttempts answers 429 with Retry-After when err is a *tooManyAttemptsError, and reports
// whether it was, so callers fall through to their own handling otherwise.
func tooManyAttempts(w http.ResponseWriter, err error) bool {
	var e *tooManyAttemptsError
	if !errors.As(err, &e) {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(e.retry.Seconds())))
	router.JSONError(w, e.Error(), http.StatusTooManyRequests)
	return true
}

type attempt struct {
	count    int
	firstTry time.Time
	lockedAt time.Time
}

// attemptLimiter locks a key (an IP or a user) out for loginLockoutTime after max failed
// attempts within loginLockoutWindow.
type attemptLimiter[K comparable] struct {
	what string // "Login", "2FA", "Password": in logs and errors
	max  int
	mu   sync.Mutex
	m    map[K]*attempt
}

func newAttemptLimiter[K comparable](what string, max int) *attemptLimiter[K] {
	return &attemptLimiter[K]{what: what, max: max, m: make(map[K]*attempt)}
}

// reserve ATOMICALLY checks the lockout and reserves an attempt slot in a single critical
// section, closing the check-then-increment race where a burst of concurrent requests could all
// pass a stale "under the limit" read. Call it BEFORE the expensive check; every attempt
// consumes a slot up front, and a success (clear) or a not-a-failure result (refund) gives it
// back. Returns a *tooManyAttemptsError while the key is locked out.
func (l *attemptLimiter[K]) reserve(key K) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	a, ok := l.m[key]
	if !ok {
		l.m[key] = &attempt{count: 1, firstTry: now}
		return nil
	}

	// Currently locked out?
	if !a.lockedAt.IsZero() {
		if remaining := loginLockoutTime - now.Sub(a.lockedAt); remaining > 0 {
			return &tooManyAttemptsError{what: strings.ToLower(l.what), retry: remaining}
		}
		// Lockout expired — reset and count this as the first attempt of a new window.
		*a = attempt{count: 1, firstTry: now}
		return nil
	}

	// Counting window expired — reset.
	if now.Sub(a.firstTry) > loginLockoutWindow {
		*a = attempt{count: 1, firstTry: now}
		return nil
	}

	// Reserve this attempt; lock once we exceed the allowance.
	a.count++
	if a.count > l.max {
		a.lockedAt = now
		log.Printf("%s rate limit: %v locked out after %d attempts", l.what, key, a.count)
		return &tooManyAttemptsError{what: strings.ToLower(l.what), retry: loginLockoutTime}
	}
	return nil
}

// refund returns a slot reserved by reserve when the attempt was not actually a failure
// (correct password, but 2FA still pending). No-op once locked.
func (l *attemptLimiter[K]) refund(key K) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a, ok := l.m[key]; ok && a.lockedAt.IsZero() && a.count > 0 {
		a.count--
		if a.count == 0 {
			delete(l.m, key)
		}
	}
}

// clear forgets a key's failed attempts after a success.
func (l *attemptLimiter[K]) clear(key K) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

// sweep drops entries whose lockout or counting window has passed, so the map can't grow
// unbounded.
func (l *attemptLimiter[K]) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, a := range l.m {
		if a.lockedAt.IsZero() {
			if now.Sub(a.firstTry) > loginLockoutWindow {
				delete(l.m, k)
			}
		} else if now.Sub(a.lockedAt) > loginLockoutTime {
			delete(l.m, k)
		}
	}
}

var (
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
	// Initialize trusted proxies from environment. If TRUSTED_PROXIES is left blank,
	// fall back to the Traefik container IP so forwarding headers are still honoured —
	// otherwise every request would appear to come from the proxy and the per-IP login
	// rate-limit would collapse into one global bucket (any 5 bad logins lock out all).
	// docker-compose already applies this fallback at the env layer; doing it here too
	// keeps it correct however the binary is launched.
	tp := strings.TrimSpace(helper.GetEnvOptional("TRUSTED_PROXIES", ""))
	if tp == "" {
		tp = strings.TrimSpace(helper.GetEnvOptional("TRAEFIK_CONTAINER_IP", ""))
	}
	helper.InitTrustedProxies(tp)
}

// cleanupRateLimitMaps removes stale attempt entries and expired TOTP replay guards so
// those maps can't grow unbounded. Registered as a routine (see Service.Start); the
// supervisor calls it on its interval.
func cleanupRateLimitMaps() error {
	now := time.Now()
	loginLimiter.sweep(now)
	totpLimiter.sweep(now)
	passwordLimiter.sweep(now)

	usedTOTPMutex.Lock()
	for userID, u := range usedTOTP {
		if now.After(u.expires) {
			delete(usedTOTP, userID)
		}
	}
	usedTOTPMutex.Unlock()
	return nil
}
