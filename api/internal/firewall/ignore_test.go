package firewall

import (
	"testing"

	"api/internal/helper"
)

// A jail never counts a trusted network (VPN ranges, the admin's extras) or any non-public address,
// and still counts everything else.
func TestJailIgnoresTrustedAndPrivate(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("HEADSCALE_IP_RANGE", "100.64.0.0/16")
	helper.SetTrustedExtras([]string{"198.51.100.7"})
	t.Cleanup(func() { helper.SetTrustedExtras(nil) })

	s := &Service{}
	for _, ip := range []string{"10.8.0.3", "100.64.0.9", "198.51.100.7", "192.168.1.20", "127.0.0.1"} {
		if !s.isIgnoredIP(ip) {
			t.Errorf("%s should be ignored", ip)
		}
	}
	for _, ip := range []string{"203.0.113.9", "198.51.100.8", "junk"} {
		if s.isIgnoredIP(ip) {
			t.Errorf("%s should be counted", ip)
		}
	}
}
