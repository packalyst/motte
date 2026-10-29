package bounded

import "time"

// Lockout locks a key out for lock once it has used more than max attempts within window.
// Attempts are reserved before they're checked, so a burst of concurrent ones can't slip past a
// stale count; a success Clears the key, an attempt that turned out not to be a failure is
// Refunded. A key it can't track (the map is full) is refused, so a flood of new keys never
// pushes out a lockout.
type Lockout[K comparable] struct {
	m      *Map[K, attempts]
	max    int
	window time.Duration
	lock   time.Duration
}

type attempts struct {
	count    int
	first    time.Time
	lockedAt time.Time
}

// FullRetry is how long a key refused because the map is full is told to wait.
const FullRetry = time.Minute

// NewLockout tracks at most size keys.
func NewLockout[K comparable](size, max int, window, lock time.Duration) *Lockout[K] {
	return &Lockout[K]{m: New[K, attempts](size, Refuse), max: max, window: window, lock: lock}
}

func (l *Lockout[K]) expiry(a *attempts) time.Time {
	if !a.lockedAt.IsZero() {
		return a.lockedAt.Add(l.lock)
	}
	return a.first.Add(l.window)
}

// Reserve takes an attempt for key. It returns 0 when the attempt may go ahead, else how long
// key is locked out, and whether this attempt is the one that locked it.
func (l *Lockout[K]) Reserve(key K, now time.Time) (retry time.Duration, locked bool) {
	tracked := l.m.Update(key, now, func(a *attempts, found bool) time.Time {
		if !found { // new, or its window or lockout has passed
			*a = attempts{count: 1, first: now}
			return l.expiry(a)
		}
		if !a.lockedAt.IsZero() {
			retry = a.lockedAt.Add(l.lock).Sub(now)
			return l.expiry(a)
		}
		a.count++
		if a.count > l.max {
			a.lockedAt = now
			retry, locked = l.lock, true
		}
		return l.expiry(a)
	})
	if !tracked {
		return FullRetry, false
	}
	return retry, locked
}

// Refund gives back an attempt that wasn't a failure. No-op once locked out.
func (l *Lockout[K]) Refund(key K, now time.Time) {
	l.m.Update(key, now, func(a *attempts, found bool) time.Time {
		if !found {
			return now // nothing to keep
		}
		if a.lockedAt.IsZero() && a.count > 0 {
			a.count--
			if a.count == 0 {
				return now
			}
		}
		return l.expiry(a)
	})
}

// Clear forgets key's attempts after a success.
func (l *Lockout[K]) Clear(key K) { l.m.Delete(key) }
