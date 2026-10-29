package bounded

import "time"

// Rate limits requests per key with a token bucket: burst at once, refilled at perSecond. A key
// it can't track (the map is full) is refused.
type Rate[K comparable] struct {
	m         *Map[K, bucket]
	perSecond float64
	burst     float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRate tracks at most max keys.
func NewRate[K comparable](max int, perSecond, burst float64) *Rate[K] {
	return &Rate[K]{m: New[K, bucket](max, Refuse), perSecond: perSecond, burst: burst}
}

// Allow takes one request from key's bucket, or reports it's empty.
func (r *Rate[K]) Allow(key K, now time.Time) bool {
	allowed := false
	tracked := r.m.Update(key, now, func(b *bucket, found bool) time.Time {
		if !found {
			b.tokens = r.burst
		} else { // under burst: the bucket expires the moment it would be full again
			b.tokens += now.Sub(b.last).Seconds() * r.perSecond
		}
		b.last = now
		if b.tokens >= 1 {
			b.tokens--
			allowed = true
		}
		// Once refilled the bucket is the same as none, so it can go.
		return now.Add(time.Duration((r.burst - b.tokens) / r.perSecond * float64(time.Second)))
	})
	return tracked && allowed
}
