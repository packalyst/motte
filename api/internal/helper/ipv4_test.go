package helper

import (
	"net"
	"net/netip"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	for _, c := range []struct {
		in, want string
		isRange  bool
	}{
		{"203.0.113.7", "203.0.113.7/32", false},
		{" 203.0.113.7 ", "203.0.113.7/32", false},
		{"203.0.113.7/24", "203.0.113.0/24", true}, // masked to the network
		{"198.51.100.9/32", "198.51.100.9/32", true},
	} {
		p, isRange, err := ParseIPv4(c.in)
		if err != nil || p.String() != c.want || isRange != c.isRange {
			t.Errorf("ParseIPv4(%q) = %v, %v, %v; want %s, %v", c.in, p, isRange, err, c.want, c.isRange)
		}
	}
	// IPv6 in any form (mapped ones wedge the nft reload), junk and empty are refused.
	for _, in := range []string{"", "junk", "2001:db8::1", "2001:db8::/32", "::ffff:203.0.113.7", "::ffff:203.0.113.0/120", "203.0.113.7/33", "203.0.113.300"} {
		if _, _, err := ParseIPv4(in); err == nil {
			t.Errorf("ParseIPv4(%q) accepted", in)
		}
	}
}

func TestOverlapsNonPublic(t *testing.T) {
	// The whole range counts, not its first address: 8.0.0.0/5 starts public but holds 10/8.
	for _, c := range []string{"0.0.0.0/0", "0.0.0.0/1", "8.0.0.0/5", "10.8.0.0/24", "100.100.100.100/32", "100.127.0.0/16",
		"127.0.0.1/32", "169.254.169.254/32", "172.20.0.0/16", "192.168.0.0/15", "224.0.0.0/3", "0.0.0.0/8"} {
		if !OverlapsNonPublic(netip.MustParsePrefix(c)) {
			t.Errorf("%s must overlap non-public space", c)
		}
	}
	for _, c := range []string{"203.0.113.0/24", "198.51.100.7/32", "100.128.0.0/16", "11.0.0.0/8", "192.169.0.0/16"} {
		if OverlapsNonPublic(netip.MustParsePrefix(c)) {
			t.Errorf("%s is public", c)
		}
	}
}

// The SSRF guard and the traffic views treat the same addresses as internal, v4 and v6.
func TestIsNonPublicIP(t *testing.T) {
	for _, ip := range []string{"169.254.169.254", "127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1",
		"100.100.100.100", "0.0.0.0", "0.1.2.3", "224.0.0.1", "::ffff:10.0.0.5", "::1", "fe80::1", "fd00::1", "ff02::1", "::"} {
		if !IsNonPublicIP(net.ParseIP(ip)) {
			t.Errorf("IsNonPublicIP(%s) = false", ip)
		}
	}
	for _, ip := range []string{"203.0.113.10", "198.51.100.1", "100.128.0.1", "::ffff:203.0.113.10", "2001:db8::1"} {
		if IsNonPublicIP(net.ParseIP(ip)) {
			t.Errorf("IsNonPublicIP(%s) = true", ip)
		}
	}
	if IsNonPublicIP(nil) {
		t.Error("nil must not count as non-public")
	}
}

func TestWithinRFC1918(t *testing.T) {
	for _, c := range []string{"10.20.20.0/24", "10.0.0.0/8", "172.31.0.0/16", "192.168.1.0/24"} {
		if !WithinRFC1918(netip.MustParsePrefix(c)) {
			t.Errorf("%s is inside RFC1918", c)
		}
	}
	// Spills out of its block (/7, /15, /11) or isn't RFC1918 at all.
	for _, c := range []string{"10.0.0.0/7", "192.168.0.0/15", "172.16.0.0/11", "100.64.0.0/24", "203.0.113.0/24"} {
		if WithinRFC1918(netip.MustParsePrefix(c)) {
			t.Errorf("%s is not inside RFC1918", c)
		}
	}
	r := RFC1918Ranges()
	if len(r) != 3 || r[0] != "10.0.0.0/8" || r[1] != "172.16.0.0/12" || r[2] != "192.168.0.0/16" {
		t.Errorf("RFC1918Ranges() = %v", r)
	}
}

func TestFreeUpperHalfIPv4(t *testing.T) {
	none := func(string) bool { return false }
	taken := map[string]bool{"10.8.0.129": true}
	for _, c := range []struct {
		cidr  string
		inUse func(string) bool
		want  string
	}{
		{"10.8.0.0/24", none, "10.8.0.128"},
		{"10.8.0.0/24", func(ip string) bool { return ip == "10.8.0.128" || taken[ip] }, "10.8.0.130"},
		{"10.8.0.0/16", none, "10.8.128.1"}, // .0 skipped
		{"10.8.0.0/30", none, "10.8.0.2"},   // tiny range: from the start, never the broadcast
		{"10.8.0.0/24", func(string) bool { return true }, ""},
		{"10.8.0.0/31", none, ""}, // pathological masks refused
		{"10.0.0.0/7", none, ""},
		{"10.8.0.1", none, ""}, // not a range
		{"", none, ""},
	} {
		if got := FreeUpperHalfIPv4(c.cidr, c.inUse); got != c.want {
			t.Errorf("%q: got %q, want %q", c.cidr, got, c.want)
		}
	}
}
