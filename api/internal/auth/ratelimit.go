package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api/internal/bounded"
	"api/internal/helper"
	"api/internal/router"
)

// Every auth limit lives here: failed-attempt lockouts (login per IP, 2FA codes and password
// re-checks per user) and how many passkey sign-ins may wait for an answer. How many Argon2id
// computations run at once is capped panel-wide by helper.Argon2IDKey.
const (
	maxLoginAttempts    = 5 // failed logins per IP (IPv6: per /64) before lockout
	maxTOTPAttempts     = 5 // failed 2FA codes per user before lockout
	maxPasswordAttempts = 5 // wrong passwords per user at step-up, unlock and password change

	maxPendingPasskeyLogins      = 1000 // passkey sign-ins waiting for an answer, in total
	maxPendingPasskeyLoginsPerIP = 5    // ... and from one IP
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

// maxTrackedKeys caps each limiter: IPs (login) or users (2FA, password). Past it, new keys are
// refused until entries expire; keys already tracked, lockouts included, are never pushed out.
const maxTrackedKeys = 100_000

// attemptLimiter locks a key (an IP or a user) out for loginLockoutTime after max failed
// attempts within loginLockoutWindow.
type attemptLimiter[K comparable] struct {
	what string // "Login", "2FA", "Password": in logs and errors
	l    *bounded.Lockout[K]
}

func newAttemptLimiter[K comparable](what string, max int) *attemptLimiter[K] {
	return &attemptLimiter[K]{what: what, l: bounded.NewLockout[K](maxTrackedKeys, max, loginLockoutWindow, loginLockoutTime)}
}

// reserve ATOMICALLY checks the lockout and reserves an attempt slot, closing the
// check-then-increment race where a burst of concurrent requests could all pass a stale "under
// the limit" read. Call it BEFORE the expensive check; every attempt consumes a slot up front,
// and a success (clear) or a not-a-failure result (refund) gives it back. Returns a
// *tooManyAttemptsError while the key is locked out.
func (l *attemptLimiter[K]) reserve(key K) error {
	retry, locked := l.l.Reserve(key, time.Now())
	if locked {
		log.Printf("%s rate limit: %v locked out", l.what, key)
	}
	if retry > 0 {
		return &tooManyAttemptsError{what: strings.ToLower(l.what), retry: retry}
	}
	return nil
}

// refund returns a slot reserved by reserve when the attempt was not actually a failure
// (correct password, but 2FA still pending). No-op once locked.
func (l *attemptLimiter[K]) refund(key K) { l.l.Refund(key, time.Now()) }

// clear forgets a key's failed attempts after a success.
func (l *attemptLimiter[K]) clear(key K) { l.l.Clear(key) }

// usedTOTP holds the last successfully-used TOTP code per user, to block replay of a captured
// code within its validity window (90s: the TOTP period plus the library's ±1 step skew).
var usedTOTP = bounded.New[int64, string](maxTrackedKeys, bounded.Refuse)

const totpReplayWindow = 90 * time.Second

var (
	errTOTPReplayed  = errors.New("2FA code already used, wait for the next code")
	errTOTPGuardFull = errors.New("too many 2FA checks right now, try again shortly")
)

// claimTOTPCode records a valid code as used, in the same step that checks it wasn't already, so
// two requests carrying the same code can't both pass. It fails when the code was used within
// its window, or when it can't be recorded (the map is full): a code that couldn't be recorded
// could be replayed, so it is refused.
func claimTOTPCode(userID int64, code string) error {
	now := time.Now()
	replayed := false
	if !usedTOTP.Update(userID, now, func(used *string, found bool) time.Time {
		if found && subtle.ConstantTimeCompare([]byte(*used), []byte(code)) == 1 {
			replayed = true
			return now.Add(totpReplayWindow) // keep the guard; its window restarts
		}
		*used = code
		return now.Add(totpReplayWindow)
	}) {
		return errTOTPGuardFull
	}
	if replayed {
		return errTOTPReplayed
	}
	return nil
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
