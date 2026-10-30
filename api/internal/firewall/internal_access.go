package firewall

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// internalCallerAllowed reports whether a request to an /internal/* endpoint may be served.
// These endpoints carry no credential (the Traefik sentinel plugin can't log in), and Traefik is
// their only caller, so access is restricted by WHERE the request physically comes from: the real
// TCP peer address (r.RemoteAddr), which, unlike a header, can't be spoofed on an established
// connection, must be Traefik's container (TRAEFIK_CONTAINER_IP) exactly. Any other address, a
// VPN client or a LAN device included, is refused, and so is every request when the address isn't
// configured. As a second layer, a request carrying edge/proxy headers is refused: those only
// appear on traffic that came through the public reverse proxy, which never routes /internal/*.
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
	got := net.ParseIP(host)
	want := net.ParseIP(strings.TrimSpace(os.Getenv("TRAEFIK_CONTAINER_IP")))
	return got != nil && want != nil && got.Equal(want)
}
