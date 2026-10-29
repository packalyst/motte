// Package bounded keeps the panel's in-memory per-key state (request rates, failed-attempt
// lockouts, short-lived tokens, flow counters) in maps with a hard size cap and a per-entry
// expiry, so nothing a client sends can grow memory without limit. Every such map in the panel
// is a bounded.Map; the cap and what happens when it's full are chosen where it's made.
package bounded

import (
	"container/list"
	"sync"
	"time"
)

// Full is what a full map does with a new key.
type Full int

const (
	// Refuse keeps every entry and turns the new key away: a flood can't push out what is
	// already tracked (a lockout, a counted flow).
	Refuse Full = iota
	// DropOldest makes room by forgetting the least recently updated key.
	DropOldest
)

const (
	sweepEvery     = time.Minute // expired entries are dropped at least this often
	fullSweepEvery = time.Second // ... and at most this often while the map is full
)

// Map is a size-capped map whose entries expire. Safe for concurrent use.
type Map[K comparable, V any] struct {
	mu    sync.Mutex
	max   int
	full  Full
	items map[K]*list.Element
	order *list.List // of *item; least recently updated first
	swept time.Time
}

type item[K comparable, V any] struct {
	key     K
	val     V
	expires time.Time
}

// New makes a map of at most max entries.
func New[K comparable, V any](max int, full Full) *Map[K, V] {
	if max < 1 {
		panic("bounded: max must be at least 1")
	}
	return &Map[K, V]{max: max, full: full, items: map[K]*list.Element{}, order: list.New()}
}

// Update runs fn on key's value under the map's lock: the stored value and true, or the zero
// value and false when key is absent or expired. fn returns when the value expires; a time not
// after now removes it. Update reports false, storing nothing, when key is new and a Refuse map
// is full; fn has run on a scratch value then, so callers check the result before acting on what
// fn decided.
func (m *Map[K, V]) Update(key K, now time.Time, fn func(v *V, found bool) time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepIfDue(now)
	if e, ok := m.items[key]; ok {
		it := e.Value.(*item[K, V])
		if now.Before(it.expires) {
			it.expires = fn(&it.val, true)
			if !now.Before(it.expires) {
				m.remove(e)
			} else {
				m.order.MoveToBack(e)
			}
			return true
		}
		m.remove(e)
	}
	var v V
	expires := fn(&v, false)
	if !now.Before(expires) {
		return true // nothing to keep
	}
	if len(m.items) >= m.max && now.Sub(m.swept) >= fullSweepEvery {
		m.sweep(now)
	}
	if len(m.items) >= m.max {
		if m.full == Refuse {
			return false
		}
		m.remove(m.order.Front())
	}
	m.items[key] = m.order.PushBack(&item[K, V]{key: key, val: v, expires: expires})
	return true
}

// Get returns key's value, or false when it is absent or expired.
func (m *Map[K, V]) Get(key K, now time.Time) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepIfDue(now)
	if e, ok := m.items[key]; ok {
		if it := e.Value.(*item[K, V]); now.Before(it.expires) {
			return it.val, true
		}
	}
	var zero V
	return zero, false
}

// Take returns key's value and removes it (a one-time token), or false when absent or expired.
func (m *Map[K, V]) Take(key K, now time.Time) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var zero V
	e, ok := m.items[key]
	if !ok {
		return zero, false
	}
	m.remove(e)
	if it := e.Value.(*item[K, V]); now.Before(it.expires) {
		return it.val, true
	}
	return zero, false
}

// Delete removes key.
func (m *Map[K, V]) Delete(key K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.items[key]; ok {
		m.remove(e)
	}
}

// Count returns how many unexpired values match.
func (m *Map[K, V]) Count(now time.Time, match func(V) bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.items {
		if it := e.Value.(*item[K, V]); now.Before(it.expires) && match(it.val) {
			n++
		}
	}
	return n
}

// Len returns how many entries are held, expired ones not yet dropped included.
func (m *Map[K, V]) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

func (m *Map[K, V]) remove(e *list.Element) {
	delete(m.items, e.Value.(*item[K, V]).key)
	m.order.Remove(e)
}

func (m *Map[K, V]) sweepIfDue(now time.Time) {
	if now.Sub(m.swept) >= sweepEvery {
		m.sweep(now)
	}
}

func (m *Map[K, V]) sweep(now time.Time) {
	for e := m.order.Front(); e != nil; {
		next := e.Next()
		if !now.Before(e.Value.(*item[K, V]).expires) {
			m.remove(e)
		}
		e = next
	}
	m.swept = now
}
