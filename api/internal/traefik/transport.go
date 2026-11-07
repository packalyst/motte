package traefik

import "api/internal/helper"

// serversTransport is how Traefik connects to an HTTPS backend: the hostname it names in the TLS
// handshake (SNI), and whether it skips checking the backend's certificate.
type serversTransport struct {
	name       string
	serverName string
	skipVerify bool
}

// skipVerifyTransport is the shared transport of the routes that only skip the certificate check.
const skipVerifyTransport = "insecure-skip-verify"

// backendTransport is the transport an HTTPS backend route needs, if any. A route that names its
// backend host gets its own one, sending its domain as the hostname: for an app that picks its
// certificate by hostname and refuses a handshake that names none (Traefik connects to an IP).
// The certificate is still checked against that hostname unless the route skips the check. A
// wildcard route has no single hostname to send, so it never names one.
func backendTransport(route DomainRouteConfig) (serversTransport, bool) {
	if !route.HTTPSBackend {
		return serversTransport{}, false
	}
	if route.BackendSNI && !helper.IsWildcardDomain(route.Domain) {
		return serversTransport{
			name:       "domain-" + helper.SanitizeDomainName(route.Domain) + "-transport",
			serverName: route.Domain,
			skipVerify: route.SkipCertVerify,
		}, true
	}
	if route.SkipCertVerify {
		return serversTransport{name: skipVerifyTransport, skipVerify: true}, true
	}
	return serversTransport{}, false
}
