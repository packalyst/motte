package geolocation

import (
	"net/netip"
	"reflect"
	"testing"
)

func ipv4(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

func TestRangeToCIDRsV4(t *testing.T) {
	cases := []struct {
		name       string
		start, end uint32
		want       []string
	}{
		{"aligned /24", ipv4(1, 0, 0, 0), ipv4(1, 0, 0, 255), []string{"1.0.0.0/24"}},
		{"aligned /23", ipv4(1, 0, 2, 0), ipv4(1, 0, 3, 255), []string{"1.0.2.0/23"}},
		{"single host", ipv4(8, 8, 8, 8), ipv4(8, 8, 8, 8), []string{"8.8.8.8/32"}},
		{"whole space", 0, 0xffffffff, []string{"0.0.0.0/0"}},
		{"top of space", ipv4(255, 255, 255, 254), ipv4(255, 255, 255, 255), []string{"255.255.255.254/31"}},
		{"unaligned 2 hosts", ipv4(1, 2, 3, 1), ipv4(1, 2, 3, 2), []string{"1.2.3.1/32", "1.2.3.2/32"}},
		// 1.2.3.1 .. 1.2.3.6  → /32, /30(.2-.5)? actually greedy: .1/32, .2/31(.2-.3), .4/31(.4-.5), .6/32
		{"unaligned span", ipv4(1, 2, 3, 1), ipv4(1, 2, 3, 6), []string{"1.2.3.1/32", "1.2.3.2/31", "1.2.3.4/31", "1.2.3.6/32"}},
		{"reversed = nil", ipv4(1, 2, 3, 5), ipv4(1, 2, 3, 4), nil},
	}
	for _, tc := range cases {
		got := rangeToCIDRsV4(tc.start, tc.end)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: rangeToCIDRsV4 = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Every CIDR produced must be a valid, canonical (network-address) prefix, and the
// blocks must exactly tile the input range with no gaps or overlaps.
func TestRangeToCIDRsV4Covers(t *testing.T) {
	start, end := ipv4(10, 20, 30, 5), ipv4(10, 20, 33, 200)
	cidrs := rangeToCIDRsV4(start, end)
	var next uint64 = uint64(start)
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("invalid CIDR %q: %v", c, err)
		}
		if p.Masked() != p {
			t.Fatalf("non-canonical CIDR %q (host bits set)", c)
		}
		lo := p.Addr().As4()
		loU := uint64(ipv4(lo[0], lo[1], lo[2], lo[3]))
		if loU != next {
			t.Fatalf("gap/overlap: block %q starts at %d, expected %d", c, loU, next)
		}
		next = loU + (uint64(1) << (32 - p.Bits()))
	}
	if next != uint64(end)+1 {
		t.Fatalf("coverage ended at %d, expected %d", next, uint64(end)+1)
	}
}

func TestV4From16(t *testing.T) {
	// IPv4-mapped form (::ffff:8.8.8.8) must round-trip.
	if v, ok := v4From16(netip.MustParseAddr("8.8.8.8").As16()); !ok || v != ipv4(8, 8, 8, 8) {
		t.Fatalf("v4From16(::ffff:8.8.8.8) = %d,%v", v, ok)
	}
	// Plain low-32 form (::8.8.8.8) — the other IP2Location IPv6 numbering — too.
	var plain [16]byte
	plain[12], plain[13], plain[14], plain[15] = 8, 8, 8, 8
	if v, ok := v4From16(plain); !ok || v != ipv4(8, 8, 8, 8) {
		t.Fatalf("v4From16(::8.8.8.8) = %d,%v", v, ok)
	}
	// Genuine IPv6 must be rejected (IPv4-only firewall).
	if _, ok := v4From16(netip.MustParseAddr("2001:db8::1").As16()); ok {
		t.Fatalf("v4From16 should reject a real IPv6 address")
	}
}
