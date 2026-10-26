package sources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"api/internal/database"
	"api/internal/logs"
)

// AdGuardWatcher watches AdGuard query logs
type AdGuardWatcher struct {
	BaseWatcher
	db      *database.DB
	config  logs.Config
	filters filterNames
}

// filterNames maps AdGuard's blocklist ids to their names, read from AdGuardHome.yaml and re-read
// only when the file changes (the log tail calls it per line).
type filterNames struct {
	mu    sync.Mutex
	path  string
	mtime time.Time
	names map[int]string
}

// name returns the blocklist name for id, or "" when it isn't known.
func (f *filterNames) name(id int) string {
	if f.path == "" {
		return ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if st, err := os.Stat(f.path); err == nil && !st.ModTime().Equal(f.mtime) {
		f.mtime, f.names = st.ModTime(), readFilterNames(f.path)
	}
	return f.names[id]
}

// readFilterNames reads the id → name of AdGuard's blocklists and allowlists.
func readFilterNames(path string) map[int]string {
	names := map[int]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return names
	}
	var conf struct {
		Filters []struct {
			ID   int    `yaml:"id"`
			Name string `yaml:"name"`
		} `yaml:"filters"`
		WhitelistFilters []struct {
			ID   int    `yaml:"id"`
			Name string `yaml:"name"`
		} `yaml:"whitelist_filters"`
	}
	if yaml.Unmarshal(data, &conf) != nil {
		return names
	}
	for _, f := range append(conf.Filters, conf.WhitelistFilters...) {
		names[f.ID] = f.Name
	}
	return names
}

// AdGuardLogEntry represents an AdGuard query log entry
type AdGuardLogEntry struct {
	T        string        `json:"T"`  // Timestamp
	QH       string        `json:"QH"` // Query hostname
	QT       string        `json:"QT"` // Query type (A, AAAA, etc.)
	IP       string        `json:"IP"` // Client IP
	Upstream string        `json:"Upstream,omitempty"`
	Elapsed  int64         `json:"Elapsed"` // nanoseconds
	Cached   bool          `json:"Cached,omitempty"`
	Answer   string        `json:"Answer,omitempty"` // Base64-encoded DNS response
	Result   AdGuardResult `json:"Result,omitempty"`
}

// AdGuardResult represents the filtering result
type AdGuardResult struct {
	IsFiltered  bool          `json:"IsFiltered,omitempty"`
	Reason      int           `json:"Reason,omitempty"`
	ServiceName string        `json:"ServiceName,omitempty"` // a blocked service (Reason 8)
	Rules       []AdGuardRule `json:"Rules,omitempty"`
	IPList      []string      `json:"IPList,omitempty"`
}

// AdGuardRule represents a matched rule
type AdGuardRule struct {
	Text         string `json:"Text,omitempty"`
	IP           string `json:"IP,omitempty"`
	FilterListID int    `json:"FilterListID,omitempty"`
}

// AdGuard Reason codes (AdGuardHome internal/filtering.Reason)
const (
	ReasonNotFiltered     = 0
	ReasonAllowList       = 1
	ReasonFiltered        = 3
	ReasonSafeBrowsing    = 4
	ReasonParental        = 5
	ReasonSafeSearch      = 7
	ReasonBlockedService  = 8
	ReasonRewritten       = 9
	ReasonRewrittenHosts  = 10
	ReasonRewrittenByRule = 11
)

// customRulesID is the list id AdGuard gives the user's own filtering rules.
const customRulesID = 0

// NewAdGuardWatcher creates a new AdGuard watcher
func NewAdGuardWatcher(db *database.DB, config logs.Config) *AdGuardWatcher {
	return &AdGuardWatcher{
		BaseWatcher: NewBaseWatcher("adguard", logs.NewFileTailer(config.AdGuardLogPath, 2*time.Second)),
		db:          db,
		config:      config,
		filters:     filterNames{path: config.AdGuardConfPath},
	}
}

// Start starts the watcher
func (w *AdGuardWatcher) Start(ctx context.Context) error {
	return w.BaseWatcher.Start(ctx, w.processLine)
}

// processLine processes a single AdGuard log line
func (w *AdGuardWatcher) processLine(line string) {
	var entry AdGuardLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return
	}

	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339Nano, entry.T)
	if err != nil {
		timestamp = time.Now()
	}

	// Determine status
	status := w.determineStatus(entry)

	// Get matched rule text
	rule := ""
	if len(entry.Result.Rules) > 0 {
		rule = entry.Result.Rules[0].Text
	}

	// Duration: nanoseconds to milliseconds
	durationMs := int(entry.Elapsed / 1000000)

	// Cached flag
	cached := 0
	if entry.Cached {
		cached = 1
	}

	// Get resolved IP from various sources
	resolvedIP := w.extractResolvedIP(entry)

	_, err = w.db.Exec(`
		INSERT INTO logs (
			logs_timestamp, logs_type, logs_src_ip, logs_domain,
			logs_dest_ip, logs_status, logs_duration, logs_cached,
			logs_query_type, logs_upstream, logs_rule, logs_rule_source
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		timestamp,
		logs.LogTypeDNS,
		entry.IP,
		entry.QH,
		resolvedIP,
		status,
		durationMs,
		cached,
		entry.QT,
		entry.Upstream,
		rule,
		w.ruleSource(entry),
	)

	if err != nil {
		// Log error but continue
	}
}

// determineStatus determines the DNS status from the result
func (w *AdGuardWatcher) determineStatus(entry AdGuardLogEntry) string {
	if entry.Cached {
		return "cached"
	}

	if entry.Result.IsFiltered {
		return "blocked"
	}

	switch entry.Result.Reason {
	case ReasonRewritten:
		return "rewritten"
	case ReasonFiltered:
		return "filtered"
	case ReasonNotFiltered:
		return "allowed"
	default:
		if len(entry.Result.IPList) > 0 {
			return "rewritten"
		}
		return "allowed"
	}
}

// ruleSource names what decided a query: the blocklist (by name) its rule came from, the user's
// own rules, a blocked service, or one of AdGuard's protections. "" when nothing matched.
func (w *AdGuardWatcher) ruleSource(entry AdGuardLogEntry) string {
	r := entry.Result
	switch r.Reason {
	case ReasonBlockedService:
		if r.ServiceName != "" {
			return "Blocked service: " + r.ServiceName
		}
		return "Blocked service"
	case ReasonSafeBrowsing:
		return "Safe browsing"
	case ReasonParental:
		return "Parental control"
	case ReasonSafeSearch:
		return "Safe search"
	case ReasonRewritten, ReasonRewrittenHosts:
		return "DNS rewrite"
	}
	if len(r.Rules) == 0 {
		return ""
	}
	id := r.Rules[0].FilterListID
	if id == customRulesID {
		return "Custom rule"
	}
	if name := w.filters.name(id); name != "" {
		return name
	}
	return fmt.Sprintf("Blocklist %d", id)
}

// extractResolvedIP extracts the resolved IP from various sources
func (w *AdGuardWatcher) extractResolvedIP(entry AdGuardLogEntry) string {
	// 1. Check IPList first (rewrites)
	if len(entry.Result.IPList) > 0 {
		return entry.Result.IPList[0]
	}

	// 2. Check Rules (for filtered entries with redirect IP)
	for _, rule := range entry.Result.Rules {
		if rule.IP != "" {
			return rule.IP
		}
	}

	// 3. Parse Answer for A/AAAA records
	if entry.Answer != "" && (entry.QT == "A" || entry.QT == "AAAA") {
		if ip := w.parseAnswerIP(entry.Answer, entry.QT); ip != "" {
			return ip
		}
	}

	return ""
}

// parseAnswerIP extracts IP from Base64-encoded DNS answer
func (w *AdGuardWatcher) parseAnswerIP(answer string, queryType string) string {
	data, err := base64.StdEncoding.DecodeString(answer)
	if err != nil || len(data) < 12 {
		return ""
	}

	// DNS header is 12 bytes
	// Skip header and question section to find answers
	pos := 12

	// Skip question section (name + 4 bytes for type/class)
	for pos < len(data) && data[pos] != 0 {
		if data[pos]&0xc0 == 0xc0 {
			pos += 2
			break
		}
		pos += int(data[pos]) + 1
	}
	if pos < len(data) && data[pos] == 0 {
		pos++ // null terminator
	}
	pos += 4 // QTYPE + QCLASS

	// Parse answer records
	answerCount := int(data[6])<<8 | int(data[7])
	for i := 0; i < answerCount && pos < len(data); i++ {
		// Skip name (could be pointer or label)
		for pos < len(data) {
			if data[pos]&0xc0 == 0xc0 {
				pos += 2
				break
			}
			if data[pos] == 0 {
				pos++
				break
			}
			pos += int(data[pos]) + 1
		}

		if pos+10 > len(data) {
			break
		}

		rtype := int(data[pos])<<8 | int(data[pos+1])
		rdlen := int(data[pos+8])<<8 | int(data[pos+9])
		pos += 10 // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

		if pos+rdlen > len(data) {
			break
		}

		// A record (type 1) = 4 bytes IPv4
		if rtype == 1 && rdlen == 4 && queryType == "A" {
			return formatIPv4(data[pos : pos+4])
		}

		// AAAA record (type 28) = 16 bytes IPv6
		if rtype == 28 && rdlen == 16 && queryType == "AAAA" {
			return formatIPv6(data[pos : pos+16])
		}

		pos += rdlen
	}

	return ""
}

// formatIPv4 formats bytes as IPv4 address
func formatIPv4(b []byte) string {
	if len(b) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// formatIPv6 formats bytes as IPv6 address
func formatIPv6(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}
