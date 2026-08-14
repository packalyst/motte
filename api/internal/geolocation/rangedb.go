package geolocation

import (
	"bufio"
	"encoding/csv"
	"io"
	"math/big"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// maxRangeRows caps how many rows a range DB will load. A defensive upper bound so a
// corrupt or hostile CSV can never exhaust memory; real IP2Location LITE files are far
// smaller. Once loaded the table is a FIXED size — nothing grows per lookup.
const maxRangeRows = 8_000_000

// asnVal / proxyVal are the tiny per-range payloads. Strings are interned at load time
// so the thousands of ranges that share one operator/type name point at one string.
type asnVal struct {
	asn  uint32
	name string
}
type proxyVal struct {
	ptype    string
	usage    string // usage_type (DCH=data-center, ISP, MOB…), higher PX tiers only
	threat   string // threat class (spam/botnet…), PX9+
	fraud    uint8  // fraud score 0-100, PX12
	hasFraud bool
}

// proxyColumns holds the CSV column indices for the optional richer proxy fields.
// They vary by IP2Proxy tier and the CSV has no header, so the indices are configurable
// (configs/geolocation.json) — a wrong guess is a config fix, not a rebuild. A value
// <= 2 (i.e. at/before proxy_type) means "field not present, skip".
type proxyColumns struct {
	usageType int
	threat    int
	fraud     int
}

// rangeRow is one [lo,hi] IP range stored as 16-byte big-endian keys (so IPv4 and IPv6
// live in one table — IPv4 as its ::ffff: mapped form, matching netip.Addr.As16()).
type rangeRow[T any] struct {
	lo, hi [16]byte
	val    T
}

// rangeTable is an immutable, sorted set of IP ranges searched by binary search.
// Reads take an RLock and never allocate or mutate; a reload builds a brand-new slice
// and swaps it under the write lock, so the old one is released for GC. Memory is a
// fixed function of the file — no accumulation across lookups or reloads.
type rangeTable[T any] struct {
	mu   sync.RWMutex
	rows []rangeRow[T]
}

// lookup returns the payload of the range containing ip, if any. Zero allocation.
func (t *rangeTable[T]) lookup(ip string) (T, bool) {
	var zero T
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return zero, false
	}
	key := addr.As16()

	t.mu.RLock()
	rows := t.rows
	t.mu.RUnlock()
	if len(rows) == 0 {
		return zero, false
	}

	// Index of the last range whose lo <= key.
	i := sort.Search(len(rows), func(i int) bool {
		return compare16(rows[i].lo, key) > 0
	}) - 1
	if i < 0 {
		return zero, false
	}
	if compare16(key, rows[i].hi) <= 0 {
		return rows[i].val, true
	}
	return zero, false
}

func (t *rangeTable[T]) count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.rows)
}

// load parses a CSV file into a fresh sorted table and swaps it in atomically. parse
// turns one record into (loDecimal, hiDecimal, payload, ok); invalid rows are skipped,
// never fatal. big.Int is used only here (at load), never on the lookup path.
func (t *rangeTable[T]) load(path string, parse func(rec []string) (string, string, T, bool)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReaderSize(f, 1<<16))
	r.ReuseRecord = true   // reuse the record slice header; field strings are still fresh copies
	r.FieldsPerRecord = -1 // tolerate variable column counts

	rows := make([]rangeRow[T], 0, 4096)
	var lo, hi big.Int
	for len(rows) < maxRangeRows {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // skip a malformed line, keep going
		}
		loStr, hiStr, val, ok := parse(rec)
		if !ok {
			continue
		}
		if _, ok := lo.SetString(loStr, 10); !ok {
			continue
		}
		if _, ok := hi.SetString(hiStr, 10); !ok {
			continue
		}
		if lo.Sign() < 0 || hi.Sign() < 0 || lo.BitLen() > 128 || hi.BitLen() > 128 {
			continue
		}
		var row rangeRow[T]
		lo.FillBytes(row.lo[:])
		hi.FillBytes(row.hi[:])
		row.val = val
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool { return compare16(rows[i].lo, rows[j].lo) < 0 })

	t.mu.Lock()
	t.rows = rows
	t.mu.Unlock()
	return nil
}

// fileExists reports whether p is an existing regular file.
func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// compare16 orders two 16-byte big-endian values: -1, 0, or 1.
func compare16(a, b [16]byte) int {
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// interner deduplicates repeated strings during a single load; the map is discarded
// afterwards, so only the unique strings survive in the table.
func newInterner() func(string) string {
	m := make(map[string]string, 4096)
	return func(s string) string {
		if v, ok := m[s]; ok {
			return v
		}
		m[s] = s
		return s
	}
}

// parseASNRow parses IP2Location LITE ASN CSV rows: ip_from, ip_to, cidr, asn, as_name.
func parseASNRow(intern func(string) string) func([]string) (string, string, asnVal, bool) {
	return func(rec []string) (string, string, asnVal, bool) {
		if len(rec) < 5 {
			return "", "", asnVal{}, false
		}
		asn, _ := strconv.ParseUint(strings.TrimSpace(rec[3]), 10, 32) // "-" -> 0
		name := strings.TrimSpace(rec[4])
		if asn == 0 && (name == "" || name == "-") {
			return "", "", asnVal{}, false
		}
		return rec[0], rec[1], asnVal{asn: uint32(asn), name: intern(name)}, true
	}
}

// parseProxyRow parses IP2Proxy LITE CSV rows. Columns 0,1 are the range and column 2
// is proxy_type (present in every tier); the richer fields are read from configurable
// indices when the row is long enough (higher tiers). Only actual proxy ranges are
// stored — a lookup miss simply means "not a proxy", keeping the table to flagged ranges.
func parseProxyRow(intern func(string) string, cols proxyColumns) func([]string) (string, string, proxyVal, bool) {
	get := func(rec []string, idx int) string {
		if idx > 2 && idx < len(rec) {
			if s := strings.TrimSpace(rec[idx]); s != "" && s != "-" {
				return s
			}
		}
		return ""
	}
	return func(rec []string) (string, string, proxyVal, bool) {
		if len(rec) < 3 {
			return "", "", proxyVal{}, false
		}
		pt := strings.TrimSpace(rec[2])
		if pt == "" || pt == "-" {
			return "", "", proxyVal{}, false
		}
		v := proxyVal{ptype: intern(pt)}
		if s := get(rec, cols.usageType); s != "" {
			v.usage = intern(s)
		}
		if s := get(rec, cols.threat); s != "" {
			v.threat = intern(s)
		}
		if s := get(rec, cols.fraud); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 100 {
				v.fraud = uint8(n)
				v.hasFraud = true
			}
		}
		return rec[0], rec[1], v, true
	}
}
