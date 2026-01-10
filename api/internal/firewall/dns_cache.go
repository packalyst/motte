package firewall

import (
	"container/list"
	"sync"
	"time"
)

const (
	dnsCacheMaxSize = 10000
	dnsCacheTTL     = 1 * time.Hour
)

// dnsEntry holds a cached reverse DNS lookup result
type dnsEntry struct {
	ip        string
	domain    string
	timestamp time.Time
}

// lruDNSCache is an LRU cache for reverse DNS lookups (IP → domain)
type lruDNSCache struct {
	items   map[string]*list.Element
	order   *list.List
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
}

func newLRUDNSCache(maxSize int, ttl time.Duration) *lruDNSCache {
	return &lruDNSCache{
		items:   make(map[string]*list.Element),
		order:   list.New(),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (c *lruDNSCache) get(ip string) (string, bool) {
	c.mu.RLock()
	elem, exists := c.items[ip]
	if !exists {
		c.mu.RUnlock()
		return "", false
	}
	entry := elem.Value.(*dnsEntry)
	if time.Since(entry.timestamp) >= c.ttl {
		c.mu.RUnlock()
		return "", false
	}
	c.mu.RUnlock()

	// Move to front (most recently used)
	c.mu.Lock()
	c.order.MoveToFront(elem)
	c.mu.Unlock()

	return entry.domain, true
}

func (c *lruDNSCache) set(ip, domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing entry
	if elem, exists := c.items[ip]; exists {
		entry := elem.Value.(*dnsEntry)
		entry.domain = domain
		entry.timestamp = time.Now()
		c.order.MoveToFront(elem)
		return
	}

	// Evict oldest if at capacity
	if c.order.Len() >= c.maxSize {
		oldest := c.order.Back()
		if oldest != nil {
			entry := oldest.Value.(*dnsEntry)
			delete(c.items, entry.ip)
			c.order.Remove(oldest)
		}
	}

	// Add new entry
	entry := &dnsEntry{ip: ip, domain: domain, timestamp: time.Now()}
	elem := c.order.PushFront(entry)
	c.items[ip] = elem
}
