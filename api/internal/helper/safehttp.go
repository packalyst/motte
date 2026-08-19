package helper

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// ssrfExtraBlocked holds ranges that net.IP's built-in predicates don't classify but that
// must still be blocked for outbound fetches (CGNAT/shared space + reserved 0.0.0.0/8).
var ssrfExtraBlocked = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"100.64.0.0/10", "0.0.0.0/8"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// SafeExternalHTTPClient returns an *http.Client for fetching operator-supplied URLs that
// must only ever reach PUBLIC hosts (e.g. remote blocklists). Its dialer validates the
// RESOLVED IP at connect time via Control, so a hostname that resolves to a public IP at
// validation time but then rebinds to an internal address (DNS-rebinding SSRF) is still
// blocked — and because the check runs on every dial, it also covers redirect hops. String
// pre-validation of the URL can't achieve this on its own (the name is re-resolved later).
func SafeExternalHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	dialer.Control = func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("refusing to dial unresolvable address %q", address)
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("refusing to connect to non-public address %s (SSRF guard)", ip)
		}
		// net.IP.IsPrivate doesn't cover CGNAT/shared space (100.64.0.0/10, RFC 6598) —
		// which this deployment uses for the Tailscale/Headscale overlay — nor the reserved
		// 0.0.0.0/8. Block them explicitly so an SSRF can't reach the VPN plane.
		for _, n := range ssrfExtraBlocked {
			if n.Contains(ip) {
				return fmt.Errorf("refusing to connect to reserved address %s (SSRF guard)", ip)
			}
		}
		return nil
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}
