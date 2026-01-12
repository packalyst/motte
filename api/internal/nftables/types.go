package nftables

import (
	"sync"
	"time"

	"api/internal/database"
)

// Table interface - each nftables table implements this
type Table interface {
	Name() string
	Family() string
	Build() (string, error)
	Priority() int
}

// Service manages all nftables operations
type Service struct {
	db     *database.DB
	tables map[string]Table

	// Debouncing
	applyMutex   sync.Mutex
	applyPending bool
	applyTimer   *time.Timer
	lastApplyErr error
	lastApplyAt  time.Time

	// Callbacks (set externally to avoid circular imports)
	broadcastFn func(channel string, data interface{})

	// Config
	debounceDelay time.Duration
}

// CountryZonesProvider provides country IP ranges (implemented by geolocation.Service)
type CountryZonesProvider interface {
	GetAllBlockedCIDRs(outboundOnly bool) ([]string, error)
}

// SyncStatus represents sync state between DB and nftables
type SyncStatus struct {
	InSync         bool          `json:"inSync"`
	LastApplyAt    time.Time     `json:"lastApplyAt,omitempty"`
	LastApplyError string        `json:"lastApplyError,omitempty"`
	ApplyPending   bool          `json:"applyPending"`
	Tables         []TableStatus `json:"tables"`
}

// TableStatus represents status for a single table
type TableStatus struct {
	Name   string         `json:"name"`
	Family string         `json:"family"`
	Exists bool           `json:"exists"`
	Stats  map[string]int `json:"stats,omitempty"`
}

// Entry types for firewall_entries table
const (
	EntryTypeIP      = "ip"
	EntryTypeRange   = "range"
	EntryTypeCountry = "country"
	EntryTypePort    = "port"
)

// Entry actions
const (
	ActionBlock = "block"
	ActionAllow = "allow"
)

// Entry directions
const (
	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"
	DirectionBoth     = "both"
)

// Entry protocols
const (
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolBoth = "both"
)

// FirewallEntry represents a unified firewall entry
type FirewallEntry struct {
	ID        int64      `json:"id"`
	EntryType string     `json:"entryType"`
	Value     string     `json:"value"`
	Action    string     `json:"action"`
	Direction string     `json:"direction"`
	Protocol  string     `json:"protocol"`
	Source    string     `json:"source"`
	Reason    string     `json:"reason,omitempty"`
	Name      string     `json:"name,omitempty"`
	Essential bool       `json:"essential"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Enabled   bool       `json:"enabled"`
	HitCount  int        `json:"hitCount"`
	CreatedAt time.Time  `json:"createdAt"`
}
