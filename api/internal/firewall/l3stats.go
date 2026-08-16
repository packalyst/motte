package firewall

import (
	"regexp"
	"strconv"
	"sync"
	"time"
)

// L3 (nftables) drop accounting. The block-set drop rules carry `counter`, but the
// firewall table is rebuilt (delete+recreate) on every apply — every auto-ban resets
// the kernel counters. So we can't read a cumulative number directly; instead a
// sampler polls the counters and stores DELTAS, which survive the rebuilds. Only the
// inbound saddr block-set drop rules carry counters, so summing every `counter packets`
// in the table sums exactly those (input + forward chains).

var (
	l3TableOnce  sync.Once
	reNftCounter = regexp.MustCompile(`counter packets (\d+) bytes \d+`)
)

func (s *Service) ensureL3Table() {
	l3TableOnce.Do(func() {
		s.db.Exec(`CREATE TABLE IF NOT EXISTS fw_drop_samples (
			ts      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			packets INTEGER NOT NULL
		)`)
		s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_fw_drop_ts ON fw_drop_samples(ts)`)
	})
}

// readDropPackets sums the packet counters on the block-set drop rules.
func (s *Service) readDropPackets() (int64, bool) {
	if s.nft == nil {
		return 0, false
	}
	out, err := s.nft.Exec("list", "table", "inet", "wgadmin_firewall")
	if err != nil {
		return 0, false
	}
	var total int64
	for _, m := range reNftCounter.FindAllStringSubmatch(string(out), -1) {
		if v, e := strconv.ParseInt(m[1], 10, 64); e == nil {
			total += v
		}
	}
	return total, true
}

// runL3CounterSampler periodically samples the kernel drop counters into delta rows.
// Because the table is rebuilt (counters reset) on every apply, we store deltas: when
// the current reading is >= the previous, add the difference; when it dropped (a
// rebuild happened), the current value is the delta since the rebuild. A few drops
// between a rebuild and the next sample can be missed — this is an approximate
// "packets blocked", not an exact kernel counter.
func (s *Service) runL3CounterSampler() {
	s.ensureL3Table()
	const interval = 20 * time.Second
	var last int64 = -1
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			cur, ok := s.readDropPackets()
			if !ok {
				last = -1 // table missing/unreadable — re-baseline on next good read
				continue
			}
			var delta int64
			switch {
			case last < 0:
				delta = 0 // first read establishes the baseline
			case cur >= last:
				delta = cur - last
			default:
				delta = cur // counters were reset by a table rebuild
			}
			last = cur
			if delta > 0 {
				s.db.Exec(`INSERT INTO fw_drop_samples (packets) VALUES (?)`, delta)
			}
			s.db.Exec(`DELETE FROM fw_drop_samples WHERE ts < datetime('now','-60 days')`)
		}
	}
}

// L3BlockedWindow returns total packets dropped by the firewall block sets within a
// SQLite datetime interval such as "-1 hour".
func (s *Service) L3BlockedWindow(interval string) int64 {
	s.ensureL3Table()
	var n int64
	s.db.QueryRow(`SELECT COALESCE(SUM(packets),0) FROM fw_drop_samples
		WHERE ts > datetime('now', ?)`, interval).Scan(&n)
	return n
}
