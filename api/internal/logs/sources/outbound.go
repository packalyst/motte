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
	db     *database.DB
	config logs.Config
	regex  *regexp.Regexp
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
	if !helper.IsVPNIP(net.ParseIP(srcIP)) {
		return
	}

	// Skip internal destinations
	if helper.IsNonPublicIP(net.ParseIP(dstIP)) {
		return
	}

	// The kernel log line carries no domain.
	_, err := w.db.Exec(`
		INSERT INTO logs (
			logs_timestamp, logs_type, logs_src_ip, logs_dest_ip,
			logs_dest_port, logs_protocol, logs_domain, logs_status
		) VALUES (?, ?, ?, ?, ?, ?, '', ?)
	`,
		time.Now(),
		logs.LogTypeOutbound,
		srcIP,
		dstIP,
		dstPort,
		proto,
		"allowed", // If we see it, it was allowed through
	)

	if err != nil {
		// Log error but continue
	}
}
