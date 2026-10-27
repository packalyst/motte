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

// IsNonPublicIP reports whether ip is anything but a public unicast address: private, loopback,
// link-local, multicast, unspecified, CGNAT (100.64.0.0/10 — the Tailscale/Headscale overlay) or
// 0.0.0.0/8. Shared by the dial-time guard below and URL checks made before a fetch.
func IsNonPublicIP(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, n := range ssrfExtraBlocked {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

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
		if IsNonPublicIP(ip) {
			return fmt.Errorf("refusing to connect to non-public address %s (SSRF guard)", ip)
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

// SafeInternalHTTPClient is for operator-supplied URLs that MAY legitimately be internal
// (e.g. a self-hosted Headscale on a private/overlay IP) but must never be steered to the
// cloud-metadata / link-local range. Unlike SafeExternalHTTPClient it ALLOWS RFC1918,
// loopback and CGNAT (those are valid internal targets here), but blocks link-local,
// multicast and the unspecified address at DIAL time on the RESOLVED ip — so a hostname
// that resolves to 169.254.169.254 (metadata) can't slip past string validation, and the
// check also covers every redirect hop.
func SafeInternalHTTPClient(timeout time.Duration) *http.Client {
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
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("refusing to connect to %s (SSRF guard: link-local/metadata)", ip)
		}
		// The IPv6 cloud-metadata endpoint is a ULA (fd00:ec2::254), so it isn't link-local; block it
		// explicitly without blocking all unique-local addresses (legit internal overlay lives there).
		if ip.Equal(net.ParseIP("fd00:ec2::254")) {
			return fmt.Errorf("refusing to connect to %s (SSRF guard: IPv6 metadata)", ip)
		}
		return nil // private / loopback / overlay / public are all legitimate internal targets
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
