package sources

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"api/internal/logs"
)

// TraefikWatcher watches Traefik access logs
type TraefikWatcher struct {
	BaseWatcher
	db     *sql.DB
	config logs.Config
}

// TraefikLogEntry represents a Traefik access log entry
type TraefikLogEntry struct {
	Time                 string `json:"time"`
	RequestHost          string `json:"RequestHost"`
	RequestMethod        string `json:"RequestMethod"`
	RequestPath          string `json:"RequestPath"`
	DownstreamStatus     int    `json:"DownstreamStatus"`
	DownstreamContentSize int   `json:"DownstreamContentSize"`
	Duration             int64  `json:"Duration"` // nanoseconds
	ClientHost           string `json:"ClientHost"`
	RouterName           string `json:"RouterName"`
	ServiceName          string `json:"ServiceName"`
	RequestProtocol      string `json:"RequestProtocol"`
}

// NewTraefikWatcher creates a new Traefik watcher
func NewTraefikWatcher(db *sql.DB, config logs.Config) *TraefikWatcher {
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

	// Only log domain routes (skip internal API, UI, etc.)
	if !strings.HasPrefix(entry.RouterName, "domain-") {
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
		entry.ClientHost,
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
