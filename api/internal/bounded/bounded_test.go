package bounded

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func put(m *Map[string, int], key string, val int, now time.Time, ttl time.Duration) bool {
	return m.Update(key, now, func(v *int, _ bool) time.Time { *v = val; return now.Add(ttl) })
}

// Values expire, Take is one-time, and an update returning a past time removes the key.
func TestMapExpiry(t *testing.T) {
	m := New[string, int](10, Refuse)
	put(m, "a", 1, t0, time.Minute)
	if v, ok := m.Get("a", t0.Add(59*time.Second)); !ok || v != 1 {
		t.Fatalf("get before expiry: %d %v", v, ok)
	}
	put(m, "short", 1, t0, time.Second)
	if _, ok := m.Get("short", t0.Add(2*time.Second)); ok { // between sweeps
		t.Fatal("value outlived its expiry")
	}
	if _, ok := m.Get("a", t0.Add(time.Minute)); ok {
		t.Fatal("value outlived its expiry")
	}
	m.Update("a", t0.Add(time.Minute), func(v *int, found bool) time.Time {
		if found || *v != 0 {
			t.Fatal("an expired value was handed back")
		}
		return t0
	})
	if m.Len() != 0 {
		t.Fatalf("%d entries after expiry and a removing update", m.Len())
	}
	m = New[string, int](10, Refuse)

	put(m, "b", 2, t0, time.Minute)
	if v, ok := m.Take("b", t0); !ok || v != 2 {
		t.Fatalf("take: %d %v", v, ok)
	}
	if _, ok := m.Take("b", t0); ok {
		t.Fatal("a value was taken twice")
	}
	put(m, "c", 3, t0, time.Minute)
	if _, ok := m.Take("c", t0.Add(time.Minute)); ok || m.Len() != 0 {
		t.Fatal("an expired value was taken, or left behind")
	}

	put(m, "d", 4, t0, time.Minute)
	m.Update("d", t0, func(*int, bool) time.Time { return t0 })
	if _, ok := m.Get("d", t0); ok {
		t.Fatal("an update returning now didn't remove the key")
	}
	if !m.Update("e", t0, func(*int, bool) time.Time { return t0 }) || m.Len() != 0 {
		t.Fatal("a new key with nothing to keep was stored")
	}
}

// A full Refuse map keeps what it has and turns new keys away until entries expire; existing keys
// still update.
func TestMapRefuse(t *testing.T) {
	m := New[string, int](3, Refuse)
	for i := 0; i < 3; i++ {
		if !put(m, fmt.Sprint(i), i, t0, time.Minute) {
			t.Fatalf("key %d refused", i)
		}
	}
	if put(m, "new", 9, t0.Add(time.Second), time.Minute) {
		t.Fatal("a new key was stored past the cap")
	}
	if m.Len() != 3 {
		t.Fatalf("map holds %d", m.Len())
	}
	if !put(m, "0", 10, t0.Add(time.Second), time.Hour) {
		t.Fatal("an existing key was refused")
	}
	if v, _ := m.Get("0", t0.Add(time.Second)); v != 10 {
		t.Fatal("existing key not updated")
	}
	// "1" and "2" expire; the next new key sweeps them and fits.
	if !put(m, "new", 9, t0.Add(time.Minute+2*time.Second), time.Minute) {
		t.Fatal("new key refused after entries expired")
	}
	if m.Len() != 2 {
		t.Fatalf("map holds %d after the sweep", m.Len())
	}
}

// A full map sweeps at most once a second, however many new keys arrive.
func TestMapFullSweepThrottled(t *testing.T) {
	m := New[string, int](1, Refuse)
	put(m, "a", 1, t0, 200*time.Millisecond) // the regular sweep runs here
	if put(m, "x", 1, t0.Add(500*time.Millisecond), time.Second) {
		t.Fatal("swept again within a second of the last sweep")
	}
	if !put(m, "y", 1, t0.Add(time.Second), time.Second) {
		t.Fatal("not swept a second later")
	}
}

// A full DropOldest map forgets the least recently updated key.
func TestMapDropOldest(t *testing.T) {
	m := New[string, int](2, DropOldest)
	put(m, "a", 1, t0, time.Hour)
	put(m, "b", 2, t0, time.Hour)
	put(m, "a", 3, t0, time.Hour) // a is now the most recent
	if !put(m, "c", 4, t0, time.Hour) {
		t.Fatal("DropOldest refused a key")
	}
	if _, ok := m.Get("b", t0); ok {
		t.Fatal("the least recently updated key was kept")
	}
	if _, ok := m.Get("a", t0); !ok {
		t.Fatal("a recently updated key was dropped")
	}
	if m.Len() != 2 {
		t.Fatalf("map holds %d", m.Len())
	}
}

// Expired entries are dropped on the regular sweep even when the map never fills.
func TestMapRegularSweep(t *testing.T) {
	m := New[string, int](10, Refuse)
	put(m, "a", 1, t0, time.Second)
	m.Get("other", t0.Add(sweepEvery+time.Second))
	if m.Len() != 0 {
		t.Fatal("expired entry not swept")
	}
}

func TestMapCount(t *testing.T) {
	m := New[string, int](10, Refuse)
	put(m, "a", 1, t0, time.Minute)
	put(m, "b", 1, t0, time.Second)
	put(m, "c", 2, t0, time.Minute)
	if n := m.Count(t0.Add(2*time.Second), func(v int) bool { return v == 1 }); n != 1 {
		t.Fatalf("count = %d", n)
	}
}

// Burst at once, then perSecond; buckets go once refilled; a full map refuses new keys.
func TestRate(t *testing.T) {
	r := NewRate[string](2, 1, 3)
	for i := 0; i < 3; i++ {
		if !r.Allow("a", t0) {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	if r.Allow("a", t0) {
		t.Fatal("request past the burst allowed")
	}
	if !r.Allow("b", t0) {
		t.Fatal("another key was limited")
	}
	if r.Allow("c", t0) {
		t.Fatal("a third key was tracked past the cap")
	}
	if !r.Allow("a", t0.Add(time.Second)) || r.Allow("a", t0.Add(time.Second)) {
		t.Fatal("not exactly one request per refill")
	}
	for i := 0; i < 3; i++ { // a long pause refills to the burst, never past it
		if !r.Allow("a", t0.Add(time.Hour)) {
			t.Fatalf("after a pause, request %d refused", i+1)
		}
	}
	if r.Allow("a", t0.Add(time.Hour)) {
		t.Fatal("a pause refilled past the burst")
	}
	// b refills fully after 1s (it used one of three tokens) and is dropped, making room.
	if !r.Allow("c", t0.Add(2*time.Second)) {
		t.Fatal("no room after a bucket refilled")
	}
}

// Lockout: max attempts, then locked for lock; refund and clear; windows and lockouts pass.
func TestLockout(t *testing.T) {
	l := NewLockout[string](10, 3, 15*time.Minute, 15*time.Minute)
	for i := 1; i <= 3; i++ {
		if r, _ := l.Reserve("a", t0); r != 0 {
			t.Fatalf("attempt %d: locked %v", i, r)
		}
	}
	if r, locked := l.Reserve("a", t0); r != 15*time.Minute || !locked {
		t.Fatalf("attempt 4: retry %v, locked %v", r, locked)
	}
	if r, locked := l.Reserve("a", t0.Add(time.Minute)); r != 14*time.Minute || locked {
		t.Fatalf("while locked: retry %v", r)
	}
	if r, _ := l.Reserve("b", t0); r != 0 {
		t.Fatalf("another key is affected: %v", r)
	}
	l.Refund("b", t0)
	if _, ok := l.m.Get("b", t0); ok {
		t.Fatal("refunding the only attempt should drop the key")
	}
	for i := 0; i < 5; i++ {
		l.Refund("a", t0) // no-op while locked, however many
	}
	if r, _ := l.Reserve("a", t0); r == 0 {
		t.Fatal("refunds lifted a lockout")
	}
	l.Clear("a")
	if r, _ := l.Reserve("a", t0); r != 0 {
		t.Fatalf("after clear: %v", r)
	}

	// The window resets the count; a passed lockout starts over.
	for i := 0; i < 2; i++ {
		l.Reserve("w", t0)
	}
	for i := 0; i < 3; i++ {
		if r, _ := l.Reserve("w", t0.Add(16*time.Minute)); r != 0 {
			t.Fatalf("new window attempt %d: %v", i+1, r)
		}
	}
	l.Reserve("w", t0.Add(16*time.Minute)) // locks
	if r, _ := l.Reserve("w", t0.Add(31*time.Minute+time.Second)); r != 0 {
		t.Fatalf("after the lockout passed: %v", r)
	}
}

// A full lockout map refuses new keys and never pushes out a locked one.
func TestLockoutFull(t *testing.T) {
	l := NewLockout[string](2, 1, time.Hour, time.Hour)
	l.Reserve("attacker", t0)
	l.Reserve("attacker", t0) // locked
	l.Reserve("x", t0)
	if r, _ := l.Reserve("y", t0); r != FullRetry {
		t.Fatalf("new key while full: %v", r)
	}
	if r, _ := l.Reserve("attacker", t0.Add(time.Second)); r == 0 {
		t.Fatal("a flood of new keys lifted a lockout")
	}
}
