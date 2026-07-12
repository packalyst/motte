package sources

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/logs"
)

// ConntrackWatcher attributes per-peer traffic to destinations using the
// kernel connection tracker. WireGuard reports total bytes per peer but no
// destinations; conntrack (with nf_conntrack_acct=1) has both.
//
// It uses two complementary sources so both short-lived and long-lived flows
// are captured:
//   - conntrack -L (polled): lists CURRENTLY OPEN flows with their live byte
//     counters, so an in-progress or keep-alive-held download is counted
//     within one poll interval instead of only when it eventually closes.
//   - conntrack -E -e DESTROY (streamed): the final byte counts when a flow
//     closes, settling anything that changed since the last poll.
//
// A shared per-flow "counted" map tracks how many bytes each flow has already
// contributed, so the two sources never double-count: each only adds the delta
// beyond what was already recorded. Results roll up into traffic_usage keyed by
// (peer_ip, dest_ip, dest_port, hour-bucket).
type ConntrackWatcher struct {
	db     *database.DB
	config logs.Config

	protoRe *regexp.Regexp
	srcRe   *regexp.Regexp
	dstRe   *regexp.Regexp
	sportRe *regexp.Regexp
	dportRe *regexp.Regexp
	bytesRe *regexp.Regexp

	pollInterval time.Duration

	cancel    context.CancelFunc
	running   atomic.Bool
	processed atomic.Int64
	lastError atomic.Value // string

	mu      sync.Mutex
	counted map[string]flowBytes // flow key -> bytes already recorded
}

type flowBytes struct {
	up   int64
	down int64
}

// NewConntrackWatcher creates a new conntrack byte-accounting watcher.
func NewConntrackWatcher(db *database.DB, config logs.Config) *ConntrackWatcher {
	w := &ConntrackWatcher{
		db:           db,
		config:       config,
		protoRe:      regexp.MustCompile(`\b(tcp|udp|udplite|icmp|icmpv6|sctp|dccp|gre)\b`),
		srcRe:        regexp.MustCompile(`src=(\d+\.\d+\.\d+\.\d+)`),
		dstRe:        regexp.MustCompile(`dst=(\d+\.\d+\.\d+\.\d+)`),
		sportRe:      regexp.MustCompile(`sport=(\d+)`),
		dportRe:      regexp.MustCompile(`dport=(\d+)`),
		bytesRe:      regexp.MustCompile(`bytes=(\d+)`),
		pollInterval: time.Duration(helper.GetEnvIntOptional("LOGS_CONNTRACK_POLL_SECONDS", 10)) * time.Second,
		counted:      make(map[string]flowBytes),
	}
	w.lastError.Store("")
	return w
}

// Name implements logs.Watcher.
func (w *ConntrackWatcher) Name() string { return "conntrack" }

// IsRunning implements logs.Watcher.
func (w *ConntrackWatcher) IsRunning() bool { return w.running.Load() }

// Processed implements logs.Watcher.
func (w *ConntrackWatcher) Processed() int64 { return w.processed.Load() }

// LastError implements logs.Watcher.
func (w *ConntrackWatcher) LastError() string {
	if v := w.lastError.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Stop implements logs.Watcher.
func (w *ConntrackWatcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
}

// Start runs the poll loop and the DESTROY event stream until ctx is cancelled.
func (w *ConntrackWatcher) Start(ctx context.Context) error {
	ctx, w.cancel = context.WithCancel(ctx)

	// Byte counters are off by default; without this, conntrack reports no
	// bytes and we'd have nothing to attribute. Write the proc knob directly
	// (the image has no sysctl binary). Best-effort — the container is
	// privileged with host networking, so this normally succeeds.
	if err := os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_acct", []byte("1\n"), 0644); err != nil {
		w.lastError.Store("could not enable nf_conntrack_acct: " + err.Error())
	}

	w.running.Store(true)
	defer w.running.Store(false)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); w.pollLoop(ctx) }()
	go func() { defer wg.Done(); w.eventLoop(ctx) }()
	wg.Wait()
	return nil
}

// pollLoop periodically lists open flows and records their byte growth.
func (w *ConntrackWatcher) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			out, err := exec.CommandContext(ctx, "conntrack", "-L").Output()
			if err != nil {
				w.lastError.Store("conntrack -L error: " + err.Error())
				continue
			}
			scanner := bufio.NewScanner(bytes.NewReader(out))
			scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
			for scanner.Scan() {
				w.processLine(scanner.Text(), false)
			}
		}
	}
}

// eventLoop streams DESTROY events and settles each flow's final bytes.
func (w *ConntrackWatcher) eventLoop(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "conntrack", "-E", "-e", "DESTROY")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		w.lastError.Store("conntrack -E pipe error: " + err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		w.lastError.Store("conntrack -E start error: " + err.Error())
		return
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		w.processLine(scanner.Text(), true)
	}
	_ = cmd.Wait()
}

// processLine parses one conntrack line (from -L or -E) and records the byte
// delta beyond what this flow has already contributed. onClose finalizes and
// forgets the flow.
func (w *ConntrackWatcher) processLine(line string, onClose bool) {
	srcs := w.srcRe.FindAllStringSubmatch(line, -1)
	dsts := w.dstRe.FindAllStringSubmatch(line, -1)
	bytesM := w.bytesRe.FindAllStringSubmatch(line, -1)
	if len(srcs) < 1 || len(dsts) < 1 || len(bytesM) < 2 {
		return // need orig src/dst plus both direction byte counters (acct on)
	}

	peerIP := srcs[0][1] // orig src = the VPN client
	destIP := dsts[0][1] // orig dst = the destination
	if !hasPrefix(peerIP, w.config.WgIPPrefix) && !hasPrefix(peerIP, w.config.HeadscaleIPPrefix) {
		return
	}
	if isPrivateIP(destIP) {
		return
	}

	curUp, _ := strconv.ParseInt(bytesM[0][1], 10, 64)   // orig direction = upload
	curDown, _ := strconv.ParseInt(bytesM[1][1], 10, 64) // reply direction = download

	sport := ""
	if m := w.sportRe.FindStringSubmatch(line); len(m) == 2 {
		sport = m[1]
	}
	destPort := 0
	if m := w.dportRe.FindStringSubmatch(line); len(m) == 2 {
		destPort, _ = strconv.Atoi(m[1])
	}
	proto := ""
	if m := w.protoRe.FindStringSubmatch(line); len(m) == 2 {
		proto = m[1]
	}

	// Flow identity: same 5-tuple across polls/close. sport distinguishes
	// concurrent connections to the same destination.
	key := peerIP + "|" + sport + "|" + destIP + "|" + strconv.Itoa(destPort) + "|" + proto

	w.mu.Lock()
	prev := w.counted[key]
	dUp := curUp - prev.up
	dDown := curDown - prev.down
	if dUp < 0 { // counter reset / flow id reuse — treat current as the delta
		dUp = curUp
	}
	if dDown < 0 {
		dDown = curDown
	}
	if onClose {
		delete(w.counted, key)
	} else {
		w.counted[key] = flowBytes{up: curUp, down: curDown}
	}
	// Bound memory if DESTROY events are ever missed for many flows.
	if len(w.counted) > 200000 {
		w.counted = make(map[string]flowBytes)
	}
	w.mu.Unlock()

	if dUp <= 0 && dDown <= 0 {
		return
	}

	bucket := time.Now().UTC().Truncate(time.Hour)
	_, err := w.db.Exec(`
		INSERT INTO traffic_usage
			(peer_ip, dest_ip, dest_port, protocol, bucket, bytes_up, bytes_down, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(peer_ip, dest_ip, dest_port, bucket) DO UPDATE SET
			bytes_up = bytes_up + excluded.bytes_up,
			bytes_down = bytes_down + excluded.bytes_down,
			updated_at = CURRENT_TIMESTAMP
	`, peerIP, destIP, destPort, proto, bucket, dUp, dDown)
	if err == nil {
		w.processed.Add(1)
		w.lastError.Store("")
	}
}

// hasPrefix is a tiny helper to avoid importing strings just for one call.
func hasPrefix(s, prefix string) bool {
	return prefix != "" && len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
