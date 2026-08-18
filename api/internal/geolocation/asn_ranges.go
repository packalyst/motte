package geolocation

import (
	"fmt"
	"log"
	"math/bits"
	"net/netip"
)

// maxASNv4CIDRs is a runaway backstop on how many CIDRs one ASN may expand to. It is
// set far above any real-world ASN (even large clouds are only a few thousand CIDRs),
// so it never truncates a legitimate block — it only stops a pathological/corrupt DB
// from exhausting memory or bloating the nft set. Truncation is logged loudly because,
// for a *block*, a partial expansion would be a coverage gap.
const maxASNv4CIDRs = 131072

// v4From16 extracts the IPv4 address from a 16-byte range key. IP2Location's
// IPv6 CSVs number the IPv4 space in one of two ways depending on the file:
//   - IPv4-mapped ::ffff:a.b.c.d  (bytes 10-11 = 0xff), and
//   - plain low 32 bits ::a.b.c.d (bytes 10-11 = 0).
// Both keep bytes 0-9 zero, so we accept either and read the address from the
// low four bytes. Returns (0,false) for genuine IPv6 keys (any non-zero byte in
// 0-9, or a non-{0x0000,0xffff} pair at 10-11) — the firewall is IPv4-only.
// The ::/96 block that the plain form overlaps holds no real ASN allocations.
func v4From16(b [16]byte) (uint32, bool) {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return 0, false
		}
	}
	mapped := b[10] == 0xff && b[11] == 0xff
	plain := b[10] == 0 && b[11] == 0
	if !mapped && !plain {
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
	var out []string
	truncated := false
	t.iterate(func(loB, hiB [16]byte, v asnVal) bool {
		if v.asn != asn {
			return true
		}
		lo, ok := v4From16(loB)
		if !ok {
			return true
		}
		hi, ok := v4From16(hiB)
		if !ok {
			return true
		}
		out = append(out, rangeToCIDRsV4(lo, hi)...)
		if len(out) > maxASNv4CIDRs {
			truncated = true
			return false // stop iterating
		}
		return true
	})
	if truncated {
		log.Printf("geolocation: ASN %d expands beyond %d CIDRs — truncating (block may be incomplete; check the ASN DB)", asn, maxASNv4CIDRs)
		return out[:maxASNv4CIDRs]
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
