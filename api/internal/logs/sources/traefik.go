package sources

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"api/internal/database"
	"api/internal/helper"
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

	// The visitor Cloudflare names, kept in the access log (see realClientIP).
	RequestCFConnectingIP string `json:"request_Cf-Connecting-Ip"`
}

// realClientIP is the visitor's IP: the CF-Connecting-IP Cloudflare sets when the request came
// from one of its edges (by the panel's live list), else the address that connected (ClientHost).
// Forwarding headers from anyone else are ignored: a direct visitor can write any address there.
func realClientIP(e *TraefikLogEntry) string {
	if helper.IsCloudflareIP(e.ClientHost) {
		if ip := net.ParseIP(strings.TrimSpace(e.RequestCFConnectingIP)); ip != nil {
			return ip.String()
		}
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
		helper.RedactSecretPath(entry.RequestPath),
		entry.RouterName,
		entry.ServiceName,
	)

	if err != nil {
		// Log error but continue
	}
}
