package helper

import (
	"net"
	"slices"
	"testing"
)

func trustedEnv(t *testing.T) {
	t.Helper()
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("HEADSCALE_IP_RANGE", "100.64.0.0/16")
	t.Cleanup(func() { SetTrustedExtras(nil) })
}

// The VPN ranges are always in and come first; extras follow, normalized and without duplicates.
func TestTrustedNetworks(t *testing.T) {
	trustedEnv(t)
	extras, err := TrustedExtrasFrom([]string{"10.8.0.0/16", " 198.51.100.7 ", "203.0.113.9/24", "203.0.113.0/24", "100.64.0.0/16", "", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.7", "203.0.113.0/24", "2001:db8::/32"}; !slices.Equal(extras, want) {
		t.Fatalf("extras = %v, want %v (locked ranges and duplicates dropped)", extras, want)
	}
	SetTrustedExtras(extras)
	if got, want := TrustedNetworks(), []string{"10.8.0.0/16", "100.64.0.0/16", "198.51.100.7", "203.0.113.0/24", "2001:db8::/32"}; !slices.Equal(got, want) {
		t.Fatalf("TrustedNetworks = %v, want %v", got, want)
	}
	for _, bad := range []string{"junk", "203.0.113.0/33", "0.0.0.0/0", "0.0.0.0/1", "::/0"} {
		if _, err := TrustedExtrasFrom([]string{bad}); err == nil {
			t.Errorf("TrustedExtrasFrom accepted %q", bad)
		}
	}
}

// Without any VPN range there is nothing locked; an invalid one is skipped.
func TestVPNRangesSkipsInvalid(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "not-a-range")
	t.Setenv("HEADSCALE_IP_RANGE", "100.64.0.0/16")
	if got := VPNRanges(); !slices.Equal(got, []string{"100.64.0.0/16"}) {
		t.Fatalf("locked = %v", got)
	}
}

func TestIsTrustedIP(t *testing.T) {
	trustedEnv(t)
	SetTrustedExtras([]string{"198.51.100.7", "203.0.113.0/24"})
	for _, ip := range []string{"10.8.3.4", "100.64.0.9", "198.51.100.7", "203.0.113.200"} {
		if !IsTrustedIP(net.ParseIP(ip)) {
			t.Errorf("%s should be trusted", ip)
		}
	}
	for _, ip := range []string{"198.51.100.8", "192.0.2.1", "100.65.0.1"} {
		if IsTrustedIP(net.ParseIP(ip)) {
			t.Errorf("%s should not be trusted", ip)
		}
	}
	if IsTrustedIP(nil) {
		t.Error("nil is not trusted")
	}
}

// The VPN check is real range math: 10.8.1.5 and 100.90.0.1 are inside, which the old text
// prefixes ("10.8.0.", "100.64.") missed.
func TestIsVPNIP(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("HEADSCALE_IP_RANGE", "100.64.0.0/10")
	for _, ip := range []string{"10.8.0.7", "10.8.1.5", "100.64.0.9", "100.90.0.1", "::ffff:10.8.0.7"} {
		if !IsVPNIP(net.ParseIP(ip)) {
			t.Errorf("%s is a VPN address", ip)
		}
	}
	for _, ip := range []string{"10.9.0.1", "100.128.0.1", "192.168.1.5", "203.0.113.9"} {
		if IsVPNIP(net.ParseIP(ip)) {
			t.Errorf("%s is not a VPN address", ip)
		}
	}
	if IsVPNIP(nil) {
		t.Error("nil is not a VPN address")
	}
}
