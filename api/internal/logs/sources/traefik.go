package sources

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"api/internal/database"
	"api/internal/logs"
)

// TraefikWatcher watches Traefik access logs
type TraefikWatcher struct {
	BaseWatcher
	db     *database.DB
	config logs.Config
}

// TraefikLogEntry represents a Traefik access log entry.
// The request_* fields come from Traefik's JSON access log when the corresponding
// header is kept via accessLog.fields.headers.names.<Name>: keep.
type TraefikLogEntry struct {
	Time                  string `json:"time"`
	RequestHost           string `json:"RequestHost"`
	RequestMethod         string `json:"RequestMethod"`
	RequestPath           string `json:"RequestPath"`
	DownstreamStatus      int    `json:"DownstreamStatus"`
	DownstreamContentSize int    `json:"DownstreamContentSize"`
	Duration              int64  `json:"Duration"` // nanoseconds
	ClientHost            string `json:"ClientHost"`
	RouterName            string `json:"RouterName"`
	ServiceName           string `json:"ServiceName"`
	RequestProtocol       string `json:"RequestProtocol"`

	// Trusted-proxy headers Traefik forwards when their names are kept.
	// Priority when computing the real client IP: CF > XFF > X-Real-IP > ClientHost.
	RequestCFConnectingIP string `json:"request_Cf-Connecting-Ip"`
	RequestXForwardedFor  string `json:"request_X-Forwarded-For"`
	RequestXRealIP        string `json:"request_X-Real-Ip"`
}

// realClientIP resolves the true visitor IP behind a trusted proxy.
// Prefers CF-Connecting-IP → first X-Forwarded-For entry → X-Real-IP → raw ClientHost.
// If Traefik's forwardedHeaders.trustedIPs isn't configured for the proxy source,
// ClientHost already equals the proxy edge IP, so the header wins here.
func realClientIP(e *TraefikLogEntry) string {
	if ip := strings.TrimSpace(e.RequestCFConnectingIP); ip != "" {
		return ip
	}
	if xff := strings.TrimSpace(e.RequestXForwardedFor); xff != "" {
		// XFF is a comma-separated chain, left is closest to the client.
		if comma := strings.Index(xff, ","); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return xff
	}
	if ip := strings.TrimSpace(e.RequestXRealIP); ip != "" {
		return ip
	}
	return e.ClientHost
}

// NewTraefikWatcher creates a new Traefik watcher
func NewTraefikWatcher(db *database.DB, config logs.Config) *TraefikWatcher {
	return &TraefikWatcher{
		BaseWatcher: NewBaseWatcher("traefik", logs.NewFileTailer(config.TraefikLogPath, 2*time.Second)),
		db:          db,
		config:      config,
	}
}

// Start starts the watcher
func (w *TraefikWatcher) Start(ctx context.Context) error {
	return w.BaseWatcher.Start(ctx, w.processLine)
}

// processLine processes a single Traefik log line
func (w *TraefikWatcher) processLine(line string) {
	var entry TraefikLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return
	}

	// Log user domain routes + catchall drops (blocked/unmatched hosts).
	// Skip internal API/UI/headscale traffic which is admin plumbing.
	allowedPrefixes := []string{"domain-", "catchall"}
	matched := false
	for _, p := range allowedPrefixes {
		if strings.HasPrefix(entry.RouterName, p) {
			matched = true
			break
		}
	}
	if !matched {
		return
	}

	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339, entry.Time)
	if err != nil {
		timestamp = time.Now()
	}

	// Duration: nanoseconds to milliseconds
	durationMs := int(entry.Duration / 1000000)

	_, err = w.db.Exec(`
		INSERT INTO logs (
			logs_timestamp, logs_type, logs_src_ip, logs_domain,
			logs_protocol, logs_status, logs_duration, logs_bytes,
			logs_method, logs_path, logs_router, logs_service
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		timestamp,
		logs.LogTypeInbound,
		realClientIP(&entry),
		entry.RequestHost,
		entry.RequestProtocol,
		entry.DownstreamStatus,
		durationMs,
		entry.DownstreamContentSize,
		entry.RequestMethod,
		entry.RequestPath,
		entry.RouterName,
		entry.ServiceName,
	)

	if err != nil {
		// Log error but continue
	}
}
