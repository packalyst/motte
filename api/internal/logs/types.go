package logs

import "time"

// LogType represents the type of log entry
type LogType string

const (
	LogTypeOutbound  LogType = "outbound"
	LogTypeInbound   LogType = "inbound"
	LogTypeDNS       LogType = "dns"
	LogTypeFirewall  LogType = "fw"
)

// LogStatus represents the status of a log entry
type LogStatus string

const (
	LogStatusAllowed   LogStatus = "allowed"
	LogStatusBlocked   LogStatus = "blocked"
	LogStatusFiltered  LogStatus = "filtered"
	LogStatusRewritten LogStatus = "rewritten"
	LogStatusCached    LogStatus = "cached"
)

// LogTypeInfo holds metadata about a log type
type LogTypeInfo struct {
	Value LogType `json:"value"`
	Label string  `json:"label"`
}

// LogStatusInfo holds metadata about a log status
type LogStatusInfo struct {
	Value LogStatus `json:"value"`
	Label string    `json:"label"`
}

// AllLogTypes returns all available log types with labels
var AllLogTypes = []LogTypeInfo{
	{Value: LogTypeDNS, Label: "DNS"},
	{Value: LogTypeInbound, Label: "Inbound"},
	{Value: LogTypeOutbound, Label: "Outbound"},
	{Value: LogTypeFirewall, Label: "Firewall"},
}

// AllLogStatuses returns all available log statuses with labels
var AllLogStatuses = []LogStatusInfo{
	{Value: LogStatusAllowed, Label: "Allowed"},
	{Value: LogStatusBlocked, Label: "Blocked"},
	{Value: LogStatusFiltered, Label: "Filtered"},
	{Value: LogStatusRewritten, Label: "Rewritten"},
	{Value: LogStatusCached, Label: "Cached"},
}

// LogEntry represents a unified log entry
type LogEntry struct {
	ID            int64     `json:"logs_id"`
	Timestamp     time.Time `json:"logs_timestamp"`
	Type          LogType   `json:"logs_type"`
	SrcIP         string    `json:"logs_src_ip"`
	SrcClientName string    `json:"logs_src_client_name,omitempty"`
	SrcCountry    string    `json:"logs_src_country,omitempty"`
	DestIP      string    `json:"logs_dest_ip,omitempty"`
	DestPort    int       `json:"logs_dest_port,omitempty"`
	DestCountry string    `json:"logs_dest_country,omitempty"`
	Domain      string    `json:"logs_domain,omitempty"`
	Protocol    string    `json:"logs_protocol,omitempty"`
	Status      string    `json:"logs_status,omitempty"`
	Duration    int       `json:"logs_duration,omitempty"`
	Bytes       int       `json:"logs_bytes,omitempty"`
	Cached      int       `json:"logs_cached,omitempty"`
	Method      string    `json:"logs_method,omitempty"`
	Path        string    `json:"logs_path,omitempty"`
	Router      string    `json:"logs_router,omitempty"`
	Service     string    `json:"logs_service,omitempty"`
	QueryType   string    `json:"logs_query_type,omitempty"`
	Upstream    string    `json:"logs_upstream,omitempty"`
	Rule        string    `json:"logs_rule,omitempty"`
}

// Config holds logs service configuration
type Config struct {
	TraefikLogPath    string
	AdGuardLogPath    string
	KernLogPath       string
	WgIPPrefix        string
	HeadscaleIPPrefix string
	MaxEntries        int
	CleanupInterval   int // minutes
	CountryInterval   int // minutes
	CountryBatchSize  int
}

// WatcherStatus represents the status of a watcher
type WatcherStatus struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	LastError string `json:"lastError,omitempty"`
	Processed int64  `json:"processed"`
}
