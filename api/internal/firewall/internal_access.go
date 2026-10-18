package firewall

import (
	"net"
	"net/http"
)

// internalCallerAllowed reports whether a request to an /internal/* endpoint may be served.
// These endpoints carry no credential (the Traefik sentinel plugin can't log in), so access is
// restricted by WHERE the request physically comes from: the real TCP peer address
// (r.RemoteAddr), which — unlike a header — cannot be spoofed on an established connection. We
// accept only loopback and private/Docker-bridge sources (the sentinel plugin reaches the
// host-networked API from the bridge subnet via host.docker.internal). As a second layer we
// also refuse any request carrying edge/proxy headers, since those only appear on traffic that
// came through the public reverse proxy — which never routes /internal/*.
//
// This replaces the previous header-only guard, which an attacker with direct network reach
// defeated simply by omitting the headers.
func internalCallerAllowed(r *http.Request) bool {
	if r.Header.Get("CF-Connecting-IP") != "" ||
		r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Real-IP") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // tolerate a bare IP with no port
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
