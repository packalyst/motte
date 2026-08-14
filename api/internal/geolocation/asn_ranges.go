package geolocation

import (
	"fmt"
	"math/bits"
	"net/netip"
)

// v4From16 extracts the IPv4 address from a 16-byte range key when it is the
// IPv4-mapped IPv6 form (::ffff:a.b.c.d) that rangeTable stores for IPv4 rows.
// Returns (0,false) for genuine IPv6 keys — the firewall is IPv4-only, so those
// are skipped. This is the same mapping netip.Addr.As16() produces, which is why
// IPv4 lookups already match these rows.
func v4From16(b [16]byte) (uint32, bool) {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return 0, false
		}
	}
	if b[10] != 0xff || b[11] != 0xff {
		return 0, false
	}
	return uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15]), true
}

// rangeToCIDRsV4 decomposes an inclusive IPv4 range [start,end] into the minimal
// list of aligned CIDR blocks (the standard greedy algorithm). uint64 math avoids
// wrapping at 255.255.255.255. Returns nil when start > end.
func rangeToCIDRsV4(start, end uint32) []string {
	if start > end {
		return nil
	}
	var out []string
	for {
		// Largest block anchored at start is limited by (a) start's alignment —
		// its number of trailing zero bits — and (b) how many addresses remain.
		hostBits := uint32(bits.TrailingZeros32(start)) // 32 when start == 0
		if maxByCount := uint32(bits.Len64(uint64(end)-uint64(start)+1)) - 1; maxByCount < hostBits {
			hostBits = maxByCount
		}
		addr := netip.AddrFrom4([4]byte{byte(start >> 24), byte(start >> 16), byte(start >> 8), byte(start)})
		out = append(out, fmt.Sprintf("%s/%d", addr.String(), 32-hostBits))

		next := uint64(start) + (uint64(1) << hostBits)
		if next > uint64(end) { // covered through end (handles the .255.255.255.255 top)
			break
		}
		start = uint32(next)
	}
	return out
}

// asnV4CIDRs scans the ASN range table for ranges owned by asn and returns their
// IPv4 CIDRs. A single linear pass under RLock — no allocation beyond the result,
// and called only when (re)caching a blocked ASN, never per packet. IPv6-only
// ranges are skipped.
func asnV4CIDRs(t *rangeTable[asnVal], asn uint32) []string {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	rows := t.rows
	t.mu.RUnlock()

	var out []string
	for i := range rows {
		if rows[i].val.asn != asn {
			continue
		}
		lo, ok := v4From16(rows[i].lo)
		if !ok {
			continue
		}
		hi, ok := v4From16(rows[i].hi)
		if !ok {
			continue
		}
		out = append(out, rangeToCIDRsV4(lo, hi)...)
	}
	return out
}

// ASNRangesV4 returns the IPv4 CIDRs owned by an ASN, or nil if the ASN DB is not
// loaded. Safe for concurrent use.
func (s *Service) ASNRangesV4(asn uint32) []string {
	s.mu.RLock()
	db := s.asnDB
	s.mu.RUnlock()
	return asnV4CIDRs(db, asn)
}

// ASNForIP returns the ASN that owns ip, or 0 if unknown or the ASN DB isn't
// loaded. Zero-allocation binary search — safe on the ban hot path.
func (s *Service) ASNForIP(ip string) uint32 {
	s.mu.RLock()
	db := s.asnDB
	s.mu.RUnlock()
	if db == nil {
		return 0
	}
	if v, ok := db.lookup(ip); ok {
		return v.asn
	}
	return 0
}
