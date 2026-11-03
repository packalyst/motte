package traefik

import (
	"net/netip"
	"slices"
	"strings"

	"api/internal/helper"
)

// lanSentinel is a private route's own VPN-only gate, used when LAN devices may use the route: the
// trusted networks the shared gate lets in, plus those devices' addresses, answering the way the
// shared gate it replaces would (silent or 403). rest is the route's middlewares without the
// shared gate. ok is false for a public route or one no LAN device may use: it then keeps the
// shared gate, so every other private route stays VPN-only.
func lanSentinel(route DomainRouteConfig, middlewares []string) (cfg *SentinelConfig, rest []string, ok bool) {
	if route.AccessMode != "vpn" {
		return nil, middlewares, false
	}
	var lan []string
	for _, s := range route.LANSources {
		if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && ip.Is4() && !ip.IsUnspecified() {
			lan = append(lan, netip.PrefixFrom(ip, 32).String())
		}
	}
	if len(lan) == 0 {
		return nil, middlewares, false
	}
	errorMode := "403"
	rest = slices.DeleteFunc(slices.Clone(middlewares), func(mw string) bool {
		base, _, _ := strings.Cut(mw, "@")
		if base == MiddlewareSentinelVPNSilent {
			errorMode = "silent"
		}
		return base == MiddlewareSentinelVPN || base == MiddlewareSentinelVPNSilent
	})
	cfg = &SentinelConfig{Enabled: true, ErrorMode: errorMode}
	cfg.IPFilter.SourceRange = append(helper.TrustedNetworks(), lan...)
	return cfg, rest, true
}
