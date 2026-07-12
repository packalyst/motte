package sources

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"api/internal/database"
	"api/internal/logs"
)

// ConntrackWatcher attributes per-peer traffic to destinations by consuming
// the kernel conntrack DESTROY event stream. WireGuard reports total bytes per
// peer but no destinations; the VPN_TRAFFIC log rule reports destinations but
// no bytes. conntrack (with nf_conntrack_acct=1) has both: on connection close
// it emits the final byte counters for each flow's original and reply tuple.
//
// It rolls the results up into the traffic_usage table, keyed by
// (peer_ip, dest_ip, dest_port, hour-bucket), so the dashboard can show
// "10.8.0.5 -> 3.1 GB to <dest>".
type ConntrackWatcher struct {
	db     *database.DB
	config logs.Config

	// Parses one DESTROY line. There are two tuples per line (orig + reply);
	// we capture ALL occurrences of each token and take [0]=orig, [1]=reply.
	srcRe   *regexp.Regexp
	dstRe   *regexp.Regexp
	dportRe *regexp.Regexp
	bytesRe *regexp.Regexp
	protoRe *regexp.Regexp

	cancel    context.CancelFunc
	running   atomic.Bool
	processed atomic.Int64
	lastError atomic.Value // string
	mu        sync.Mutex
}

// NewConntrackWatcher creates a new conntrack byte-accounting watcher.
func NewConntrackWatcher(db *database.DB, config logs.Config) *ConntrackWatcher {
	w := &ConntrackWatcher{
		db:      db,
		config:  config,
		srcRe:   regexp.MustCompile(`src=(\d+\.\d+\.\d+\.\d+)`),
		dstRe:   regexp.MustCompile(`dst=(\d+\.\d+\.\d+\.\d+)`),
		dportRe: regexp.MustCompile(`dport=(\d+)`),
		bytesRe: regexp.MustCompile(`bytes=(\d+)`),
		protoRe: regexp.MustCompile(`\[DESTROY\]\s+(\w+)`),
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

// Start begins consuming the conntrack event stream until ctx is cancelled.
func (w *ConntrackWatcher) Start(ctx context.Context) error {
	ctx, w.cancel = context.WithCancel(ctx)

	// Byte counters are off by default; without this, conntrack reports no
	// bytes and we'd have nothing to attribute. Best-effort — the container
	// is privileged with host networking, so this normally succeeds.
	if out, err := exec.Command("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1").CombinedOutput(); err != nil {
		w.lastError.Store("could not enable nf_conntrack_acct: " + string(out))
	}

	// -E: event mode, -e DESTROY: only closed flows (final byte counts).
	cmd := exec.CommandContext(ctx, "conntrack", "-E", "-e", "DESTROY")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		w.lastError.Store("conntrack pipe error: " + err.Error())
		return err
	}
	if err := cmd.Start(); err != nil {
		// conntrack not installed / not permitted — record and exit gracefully.
		w.lastError.Store("conntrack start error: " + err.Error())
		return err
	}

	w.running.Store(true)
	defer w.running.Store(false)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		w.processLine(scanner.Text())
	}

	// Wait for the process to reap; ignore the error if we cancelled it.
	_ = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err := scanner.Err(); err != nil {
		w.lastError.Store(err.Error())
		return err
	}
	return nil
}

// processLine parses a single DESTROY event and rolls its bytes into the DB.
func (w *ConntrackWatcher) processLine(line string) {
	srcs := w.srcRe.FindAllStringSubmatch(line, -1)
	dsts := w.dstRe.FindAllStringSubmatch(line, -1)
	bytesM := w.bytesRe.FindAllStringSubmatch(line, -1)
	dports := w.dportRe.FindAllStringSubmatch(line, -1)

	// Need the original tuple (src/dst/dport) plus both byte counters.
	if len(srcs) < 1 || len(dsts) < 1 || len(bytesM) < 2 {
		return
	}

	peerIP := srcs[0][1] // orig src = the VPN client
	destIP := dsts[0][1] // orig dst = the destination

	// Only attribute traffic originating from a VPN client.
	if !hasPrefix(peerIP, w.config.WgIPPrefix) && !hasPrefix(peerIP, w.config.HeadscaleIPPrefix) {
		return
	}
	// Ignore purely internal destinations.
	if isPrivateIP(destIP) {
		return
	}

	destPort := 0
	if len(dports) >= 1 {
		destPort, _ = strconv.Atoi(dports[0][1])
	}
	bytesUp, _ := strconv.Atoi(bytesM[0][1])   // orig direction = upload
	bytesDown, _ := strconv.Atoi(bytesM[1][1]) // reply direction = download
	if bytesUp == 0 && bytesDown == 0 {
		return // accounting disabled or empty flow
	}

	proto := ""
	if m := w.protoRe.FindStringSubmatch(line); len(m) == 2 {
		proto = m[1]
	}

	// Hour bucket keeps the rollup small while allowing time-range queries.
	bucket := time.Now().UTC().Truncate(time.Hour)

	_, err := w.db.Exec(`
		INSERT INTO traffic_usage
			(peer_ip, dest_ip, dest_port, protocol, bucket, bytes_up, bytes_down, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(peer_ip, dest_ip, dest_port, bucket) DO UPDATE SET
			bytes_up = bytes_up + excluded.bytes_up,
			bytes_down = bytes_down + excluded.bytes_down,
			updated_at = CURRENT_TIMESTAMP
	`, peerIP, destIP, destPort, proto, bucket, bytesUp, bytesDown)
	if err == nil {
		w.processed.Add(1)
		w.lastError.Store("")
	}
}

// hasPrefix is a tiny helper to avoid importing strings just for one call.
func hasPrefix(s, prefix string) bool {
	return prefix != "" && len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
