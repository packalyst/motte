package helper

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

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
