package helper

import "testing"

// IPv4 counts per address, IPv6 per /64; anything else passes through unchanged.
func TestRateKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":                "192.0.2.7",
		"::ffff:192.0.2.7":         "192.0.2.7",
		"2001:db8:1:2:aaaa::1":     "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff::": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":          "2001:db8:1:3::/64",
		"fe80::1%eth0":             "fe80::/64",
		"not-an-ip":                "not-an-ip",
		"":                         "",
	} {
		if got := RateKey(in); got != want {
			t.Errorf("RateKey(%q) = %q, want %q", in, got, want)
		}
	}
}
