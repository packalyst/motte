package nftables

import (
	"database/sql"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"api/internal/database"
	"api/internal/helper"
)

// CloudflareOnlyTable optionally restricts inbound access to HTTPS (443) to Cloudflare's
// edge ranges only — so nobody can bypass Cloudflare by hitting the server's raw IP. It is
// a SEPARATE, clearly-named table (inet motte_cf_only), so it is obvious in `nft list
// ruleset` what it does.
//
// Port 80 stays open here: Let's Encrypt validates from addresses it doesn't publish, so
// the kernel can't tell it apart. Traefik gates port 80 instead (the sentinel "gate", fed
// by WebGateSources): the certificate check passes, any other request from outside these
// sources is dropped silently.
//
// Driven by the `web_cloudflare_only` setting:
//   - OFF (default): an EMPTY shell — 80/443 stay open to everyone.
//   - ON: an input-hook chain (priority -10, BEFORE the main firewall at 0) that
//     accepts 443 from Cloudflare — plus loopback, the Docker bridge, WireGuard
//     and Headscale so an admin is never locked out — and drops it from every other
//     source. Before that, a nat chain hands IPv4 443 from every other source to
//     Traefik's narrow "direct" entrance, which serves only the DERP relay and the
//     proxy domain's triggers and drops the rest (see directRules).
//
// Fail-open: if disabled, or the Cloudflare list is somehow empty,
// it emits an empty table so it can NEVER drop all web traffic.
type CloudflareOnlyTable struct {
	db *database.DB
}

// NewCloudflareOnlyTable creates the Cloudflare-only table builder.
func NewCloudflareOnlyTable(db *database.DB) *CloudflareOnlyTable {
	return &CloudflareOnlyTable{db: db}
}

func (t *CloudflareOnlyTable) Name() string   { return "motte_cf_only" }
func (t *CloudflareOnlyTable) Family() string { return "inet" }

// Priority orders this table's emission before the main firewall (10); the chain hook
// priority (-10) is what actually orders kernel evaluation (before the main
// firewall at 0).
func (t *CloudflareOnlyTable) Priority() int { return 6 }

func (t *CloudflareOnlyTable) Build() (string, error) {
	var sb strings.Builder
	// Idempotent create/delete/define, mirroring the other tables.
	sb.WriteString("table inet motte_cf_only\ndelete table inet motte_cf_only\n\n")

	v4, v6 := splitCIDRs(helper.CloudflareCIDRs())

	// FAIL OPEN: never risk dropping all web access. If the toggle is off, or we have
	// no Cloudflare ranges to allow, emit an empty table (no filtering).
	if !t.restrictEnabled() || len(v4)+len(v6) == 0 {
		sb.WriteString("table inet motte_cf_only {\n}\n")
		return sb.String(), nil
	}

	trusted := TrustedAdminSources() // loopback, Docker bridge, WireGuard, Headscale (v4)

	sb.WriteString("table inet motte_cf_only {\n")
	if len(v4) > 0 {
		sb.WriteString(BuildSet("cf_v4", "ipv4_addr", []string{"interval", "auto-merge"}, v4))
	}
	if len(v6) > 0 {
		sb.WriteString(BuildSet("cf_v6", "ipv6_addr", []string{"interval", "auto-merge"}, v6))
	}
	lan := t.lanRouteRules()
	if direct := directRules(v4, v6, trusted, lan); direct != nil {
		sb.WriteString(BuildChain("direct", "nat", "prerouting", -110, "accept", direct))
	}
	// Two chains, both priority -10 (before the main firewall):
	//   - input: host-destined HTTPS (a host-networked service, if any).
	//   - forward: Traefik's 443 is Docker-PUBLISHED, so that traffic is DNAT'd and
	//     FORWARDED to the container — it never reaches the input hook. Scope the forward
	//     rules to `ct status dnat` so only externally-published traffic is filtered and
	//     WireGuard / container-to-container forwarding is untouched.
	sb.WriteString(BuildChain("input", "filter", "input", -10, "accept", cfRules(v4, v6, trusted, lan, "")))
	sb.WriteString(BuildChain("forward", "filter", "forward", -10, "accept", cfRules(v4, v6, trusted, lan, "ct status dnat ")))
	sb.WriteString("}\n")
	return sb.String(), nil
}

const cfHTTPS = "tcp dport " + TraefikHTTPSPort

// cfAllowed lists the sources that reach Traefik's HTTPS as it is: the trusted local/VPN sources,
// LAN devices let in to private domain routes, and Cloudflare. prefix starts and verdict ends
// each rule.
func cfAllowed(v4, v6, trusted, lan []string, prefix, verdict string) []string {
	rules := []string{
		"# Always-allowed local/VPN sources reach HTTPS (never lock the admin out).",
		prefix + "ip saddr { " + strings.Join(trusted, ", ") + " } " + cfHTTPS + " " + verdict,
		prefix + "ip6 saddr ::1/128 " + cfHTTPS + " " + verdict,
	}
	if len(lan) > 0 {
		rules = append(rules, "# LAN devices let in to private domain routes (the LAN table and Traefik decide the rest).")
		for _, r := range lan {
			rules = append(rules, prefix+r+" "+cfHTTPS+" "+verdict)
		}
	}
	rules = append(rules, "# Cloudflare edge ranges — the only public source allowed to reach "+TraefikHTTPSPort+".")
	if len(v4) > 0 {
		rules = append(rules, prefix+"ip saddr @cf_v4 "+cfHTTPS+" "+verdict)
	}
	if len(v6) > 0 {
		rules = append(rules, prefix+"ip6 saddr @cf_v6 "+cfHTTPS+" "+verdict)
	}
	return rules
}

// cfRules builds the accept-Cloudflare-and-trusted / drop-everyone-else rules for HTTPS.
// prefix is prepended to each rule — "" for the input chain, "ct status dnat " for
// the forward chain (so it only matches externally-published, DNAT'd traffic).
func cfRules(v4, v6, trusted, lan []string, prefix string) []string {
	return append(cfAllowed(v4, v6, trusted, lan, prefix, "accept"),
		"# Log (rate-limited) then drop "+TraefikHTTPSPort+" from every other source. Port 80 is gated in Traefik.",
		prefix+cfHTTPS+` limit rate 5/minute log prefix "CF_ONLY_DROP: "`,
		prefix+cfHTTPS+" drop",
	)
}

// directRules hands IPv4 HTTPS to the box from any source not allowed above to Traefik's "direct"
// entrance instead of dropping it: the DERP relay and the proxy domain's triggers are dialled
// directly, never through Cloudflare, and that entrance serves only those (everything else there
// is dropped). It runs before Docker's own nat (priority -110), and the first nat decision is
// the one kept. Only traffic to the box's own addresses is handed over, never traffic passing
// through it. nil — so 443 stays dropped — when Traefik's address or the entrance's port is
// missing or invalid.
func directRules(v4, v6, trusted, lan []string) []string {
	ip, err := helper.TraefikIP()
	port, ok := helper.TraefikDirectPort()
	if err != nil || !ok || strconv.Itoa(port) == TraefikHTTPSPort {
		log.Printf("nftables/cf_only: no direct entrance (TRAEFIK_CONTAINER_IP / TRAEFIK_DIRECT_PORT): non-Cloudflare HTTPS stays dropped")
		return nil
	}
	return append(cfAllowed(v4, v6, trusted, lan, "", "return"),
		"# Every other source: only the direct entrance, never the sites behind Cloudflare.",
		"meta nfproto ipv4 fib daddr type local "+cfHTTPS+" dnat ip to "+ip.String()+":"+strconv.Itoa(port),
	)
}

// lanRouteRules matches each LAN device let in to a private domain route, on its own LAN interface
// and address (domains: LANRouteAccess). On a read error none is let in.
func (t *CloudflareOnlyTable) lanRouteRules() []string {
	devs, err := t.db.LANRouteDevices()
	if err != nil {
		log.Printf("nftables/cf_only: LAN devices on private routes: %v", err)
		return nil
	}
	var out []string
	for _, d := range devs {
		if d.Iface == "" || SanitizeElement(d.Iface) != d.Iface || !ValidateIPv4OrCIDR(d.IP) || strings.Contains(d.IP, "/") {
			continue
		}
		out = append(out, `iifname "`+d.Iface+`" ip saddr `+d.IP)
	}
	return out
}

// lastCFOnlyRestrict remembers the last successfully-read value. A genuinely-absent setting
// (sql.ErrNoRows) means off, but a TRANSIENT DB error during a rebuild must NOT silently drop
// Cloudflare-only protection (that would re-open 80/443 to the internet) — on such an error we
// keep the last-known state instead of failing open.
var lastCFOnlyRestrict atomic.Bool

// restrictEnabled reports whether 80/443 should be Cloudflare-only. True only when
// `web_cloudflare_only` is explicitly "on"; a missing setting is off; a transient read error
// keeps whatever was last known (so a DB hiccup can't silently expose the web ports).
func (t *CloudflareOnlyTable) restrictEnabled() bool {
	if t.db == nil {
		return false
	}
	var v string
	err := t.db.QueryRow(`SELECT value FROM settings WHERE key = ? AND encrypted = 0`, "web_cloudflare_only").Scan(&v)
	if err == sql.ErrNoRows { // genuinely not configured → off
		lastCFOnlyRestrict.Store(false)
		return false
	}
	if err != nil { // transient DB error → keep last-known state, don't strip protection
		return lastCFOnlyRestrict.Load()
	}
	on := strings.EqualFold(strings.TrimSpace(v), "on")
	lastCFOnlyRestrict.Store(on)
	return on
}

// WebGateSources is who may use port 80 while Cloudflare-only is on: Cloudflare's ranges and
// the trusted admin sources, the same sources the 443 rule accepts. It returns nil when
// Cloudflare-only is off (or the Cloudflare list is empty, where the 443 rule fails open too):
// everyone may.
func (t *CloudflareOnlyTable) WebGateSources() []string {
	cf := helper.CloudflareCIDRs()
	if !t.restrictEnabled() || len(cf) == 0 {
		return nil
	}
	return append(append(TrustedAdminSources(), "::1/128"), cf...)
}

// splitCIDRs partitions CIDR strings into IPv4 and IPv6 (v6 = contains ':').
func splitCIDRs(cidrs []string) (v4, v6 []string) {
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			v6 = append(v6, c)
		} else {
			v4 = append(v4, c)
		}
	}
	return v4, v6
}

// TrustedAdminSources returns the CIDRs that keep reaching the web ports with Cloudflare-only on,
// so an admin can never be locked out of their own panel:
//   - loopback
//   - the Docker bridge (DOCKER_SUBNET) so Traefik keeps reaching the API
//   - the WireGuard range (WG_IP_RANGE) — admins on the WG VPN
//   - the Headscale/Tailscale overlay (HEADSCALE_IP_RANGE) — admins on the Tailnet
//
// The ranges come from the same env vars the rest of the stack uses; each has a sane
// fallback matching .env.example so a missing/garbled var can never drop a trusted source.
func TrustedAdminSources() []string {
	out := []string{"127.0.0.0/8"}
	out = append(out, helper.DockerSubnet())
	if c := validCIDROr(os.Getenv("WG_IP_RANGE"), "10.8.0.0/16"); c != "" {
		out = append(out, c)
	}
	if c := validCIDROr(os.Getenv("HEADSCALE_IP_RANGE"), "100.64.0.0/16"); c != "" {
		out = append(out, c)
	}
	return out
}

func validCIDROr(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v != "" {
		if _, _, err := net.ParseCIDR(v); err == nil {
			return v
		}
	}
	if _, _, err := net.ParseCIDR(fallback); err == nil {
		return fallback
	}
	return ""
}
