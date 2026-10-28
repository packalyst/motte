package helper

import (
	"net/http"
	"testing"
)

// These lock in the client-IP trust model (ADR-0007). The IP drives per-IP login rate-limiting,
// audit logs and the Cloudflare-only gate, so a spoofable source here is a real vulnerability.

func req(remoteAddr string, headers map[string]string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestGetClientIP_UntrustedPeerCannotSpoof(t *testing.T) {
	// No trusted proxies configured at all → fail closed: forwarding headers are ignored and
	// every request is attributed to the immediate socket peer.
	InitTrustedProxies("")
	got := GetClientIP(req("203.0.113.9:5555", map[string]string{
		"X-Forwarded-For":  "1.1.1.1",
		"CF-Connecting-IP": "2.2.2.2",
	}))
	if got != "203.0.113.9" {
		t.Fatalf("untrusted peer must be used verbatim, got %q", got)
	}

	// Even WITH a trusted-proxy list, a direct (untrusted) caller's spoofed headers are ignored.
	InitTrustedProxies("172.18.0.2")
	got = GetClientIP(req("203.0.113.9:5555", map[string]string{"X-Forwarded-For": "1.1.1.1"}))
	if got != "203.0.113.9" {
		t.Fatalf("spoofed XFF from an untrusted peer must be ignored, got %q", got)
	}
}

func TestGetClientIP_TrustedProxyUsesRightmostRealClient(t *testing.T) {
	InitTrustedProxies("172.18.0.2")
	// XFF is client-controlled on the LEFT; the real client is the right-most non-proxy entry.
	// 9.9.9.9 is the spoofable left value and must NOT win over the genuine 1.2.3.4.
	got := GetClientIP(req("172.18.0.2:4000", map[string]string{"X-Forwarded-For": "9.9.9.9, 1.2.3.4"}))
	if got != "1.2.3.4" {
		t.Fatalf("expected the right-most real client 1.2.3.4, got %q", got)
	}
}

func TestGetClientIP_CloudflareConnectingIPHonouredOnlyBehindCF(t *testing.T) {
	InitTrustedProxies("172.18.0.2")

	// Chain ends at a real Cloudflare edge IP → CF-Connecting-IP is authoritative.
	got := GetClientIP(req("172.18.0.2:4000", map[string]string{
		"X-Forwarded-For":  "173.245.48.1", // inside Cloudflare's 173.245.48.0/20
		"CF-Connecting-IP": "5.6.7.8",
	}))
	if got != "5.6.7.8" {
		t.Fatalf("behind Cloudflare, CF-Connecting-IP should win, got %q", got)
	}

	// No Cloudflare hop in the chain → a forged CF-Connecting-IP must be ignored, falling back
	// to the right-most real XFF entry.
	got = GetClientIP(req("172.18.0.2:4000", map[string]string{
		"X-Forwarded-For":  "1.2.3.4",
		"CF-Connecting-IP": "6.6.6.6", // forged
	}))
	if got != "1.2.3.4" {
		t.Fatalf("forged CF-Connecting-IP (no CF hop) must be ignored, got %q", got)
	}
}

func TestIsTrustedProxy_BareIPEntry(t *testing.T) {
	// The default deployment falls back to TRAEFIK_CONTAINER_IP, a bare IP (no /32). It must be
	// accepted as a single-host entry, and nothing else trusted.
	InitTrustedProxies("172.18.0.2")
	if !IsTrustedProxy("172.18.0.2") {
		t.Fatal("the configured bare container IP must be trusted")
	}
	if IsTrustedProxy("172.18.0.3") {
		t.Fatal("a neighbouring IP must NOT be trusted")
	}
}

// Secrets carried in a URL path never reach a log.
func TestRedactSecretPath(t *testing.T) {
	for in, want := range map[string]string{
		"/api/restart/k3y":    "/api/restart/[redacted]",
		"/api/hook/a/b":       "/api/hook/[redacted]",
		"/agent/0123abcd":     "/agent/[redacted]",
		"/api/fleet/machines": "/api/fleet/machines",
		"/agent":              "/agent",
	} {
		if got := RedactSecretPath(in); got != want {
			t.Errorf("RedactSecretPath(%q) = %q, want %q", in, got, want)
		}
	}
}
