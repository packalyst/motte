package sources

import (
	"context"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/logs"
)

// OutboundWatcher watches kernel VPN traffic logs
type OutboundWatcher struct {
	BaseWatcher
	db       *database.DB
	config   logs.Config
	regex    *regexp.Regexp
	dnsCache *DNSCache
}

// DNSCache provides reverse DNS caching with max size
type DNSCache struct {
	cache   map[string]string
	maxSize int
}

// NewDNSCache creates a new DNS cache with max 10000 entries
func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache:   make(map[string]string),
		maxSize: 10000,
	}
}

// Get returns cached domain or empty string
func (c *DNSCache) Get(ip string) string {
	if domain, ok := c.cache[ip]; ok {
		return domain
	}
	return ""
}

// Set caches a domain for an IP
func (c *DNSCache) Set(ip, domain string) {
	// Evict half when at capacity
	if len(c.cache) >= c.maxSize {
		i := 0
		for k := range c.cache {
			delete(c.cache, k)
			i++
			if i >= c.maxSize/2 {
				break
			}
		}
	}
	c.cache[ip] = domain
}

// NewOutboundWatcher creates a new outbound traffic watcher
func NewOutboundWatcher(db *database.DB, config logs.Config) *OutboundWatcher {
	// Try kern.log first, fall back to syslog
	logPath := config.KernLogPath
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		logPath = "/var/log/syslog"
	}

	return &OutboundWatcher{
		BaseWatcher: NewBaseWatcher("outbound", logs.NewFileTailer(logPath, 2*time.Second)),
		db:          db,
		config:      config,
		regex:       regexp.MustCompile(`VPN_TRAFFIC:.*SRC=(\d+\.\d+\.\d+\.\d+).*DST=(\d+\.\d+\.\d+\.\d+).*PROTO=(\w+)(?:.*DPT=(\d+))?`),
		dnsCache:    NewDNSCache(),
	}
}

// Start starts the watcher
func (w *OutboundWatcher) Start(ctx context.Context) error {
	return w.BaseWatcher.Start(ctx, w.processLine)
}

// processLine processes a single kernel log line
func (w *OutboundWatcher) processLine(line string) {
	if !strings.Contains(line, "VPN_TRAFFIC") {
		return
	}

	matches := w.regex.FindStringSubmatch(line)
	if len(matches) < 4 {
		return
	}

	srcIP := matches[1]
	dstIP := matches[2]
	proto := strings.ToLower(matches[3])
	dstPort := 0
	if len(matches) >= 5 && matches[4] != "" {
		dstPort, _ = strconv.Atoi(matches[4])
	}

	// Only VPN client traffic
	if !strings.HasPrefix(srcIP, w.config.WgIPPrefix) && !strings.HasPrefix(srcIP, w.config.HeadscaleIPPrefix) {
		return
	}

	// Skip internal destinations
	if helper.IsNonPublicIP(net.ParseIP(dstIP)) {
		return
	}

	// Check DNS cache for domain
	domain := w.dnsCache.Get(dstIP)

	_, err := w.db.Exec(`
		INSERT INTO logs (
			logs_timestamp, logs_type, logs_src_ip, logs_dest_ip,
			logs_dest_port, logs_protocol, logs_domain, logs_status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		time.Now(),
		logs.LogTypeOutbound,
		srcIP,
		dstIP,
		dstPort,
		proto,
		domain,
		"allowed", // If we see it, it was allowed through
	)

	if err != nil {
		// Log error but continue
	}
}
