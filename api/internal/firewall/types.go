package firewall

import (
	"context"
	"net"
	"sync"
	"time"

	"api/internal/database"
	"api/internal/geolocation"
	"api/internal/helper"
	"api/internal/nftables"
)

// jailMonitor tracks a running jail monitor
type jailMonitor struct {
	cancel context.CancelFunc
	name   string
}

// jailConfig holds config needed for jail monitoring (internal use)
type jailConfig struct {
	ID          int64
	Name        string
	LogFile     string
	FilterRegex string
	MaxRetry    int
	FindTime    int
	BanTime     int
	LastLogPos  int64
	Enabled     bool
}

// blockCache caches blocked IPs and parsed CIDR ranges to avoid repeated DB queries
type blockCache struct {
	mu         sync.RWMutex
	blockedIPs map[string]bool // direct IP lookups
	ranges     []*net.IPNet    // parsed CIDR ranges
	updatedAt  time.Time
	ttl        time.Duration
}

// Service handles firewall operations
type Service struct {
	db           *database.DB
	dbMutex      sync.RWMutex
	config       Config
	dnsCache     *lruDNSCache
	blockCache   *blockCache            // cached blocked IPs/ranges for fast lookup
	ctx          context.Context
	cancel       context.CancelFunc
	jailMonitors map[int64]*jailMonitor
	jailMutex    sync.RWMutex
	nft          *nftables.Service      // nftables service for rule application
	geo          *geolocation.Service   // geolocation service for country zones
}

// Config holds firewall configuration
type Config struct {
	EssentialPorts    []helper.EssentialPort `json:"-"`
	IgnoreNetworks    []string               `json:"ignoreNetworks"`
	MaxAttempts       int                    `json:"maxAttempts"`
	DataDir           string                 `json:"-"`
	WgPort            int                    `json:"-"`
	WgIPPrefix        string                 `json:"-"`
	HeadscaleIPPrefix string                 `json:"-"`
	JailCheckInterval int                    `json:"-"`
	CleanupInterval   int                    `json:"-"`
	DNSLookupTimeout  int                    `json:"-"`
	ServerIP          string                 `json:"-"` // Server's own IP for self-protection
}

// Jail represents a blocking rule configuration (fail2ban-style)
type Jail struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	Enabled           bool   `json:"enabled"`
	LogFile           string `json:"logFile"`
	FilterRegex       string `json:"filterRegex"`
	MaxRetry          int    `json:"maxRetry"`
	FindTime          int    `json:"findTime"`
	BanTime           int    `json:"banTime"`
	Port              string `json:"port"`
	Action            string `json:"action"`
	CurrentlyBanned   int    `json:"currentlyBanned"`
	TotalBanned       int    `json:"totalBanned"`
	EscalateEnabled   bool   `json:"escalateEnabled"`
	EscalateThreshold int    `json:"escalateThreshold"`
	EscalateWindow    int    `json:"escalateWindow"`
}

// BlocklistSource represents a blocklist source configuration
type BlocklistSource struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	URL      string   `json:"url,omitempty"`
	Ranges   []string `json:"ranges,omitempty"`
	MinScore int      `json:"minScore,omitempty"`
	Count    int      `json:"count,omitempty"`
}
