package nftables

import (
	"database/sql"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"api/internal/database"
	"api/internal/helper"
)

// CloudflareOnlyTable optionally restricts inbound access to the web ports (80/443)
// to Cloudflare's edge ranges only — so nobody can bypass Cloudflare by hitting the
// server's raw IP. It is a SEPARATE, clearly-named table (inet motte_cf_only), so it is
// obvious in `nft list ruleset` what it does.
//
// Driven by the `web_cloudflare_only` setting:
//   - OFF (default): an EMPTY shell — 80/443 stay open to everyone.
//   - ON: an input-hook chain (priority -10, BEFORE the main firewall at 0) that
//     accepts 80/443 from Cloudflare — plus loopback, the Docker bridge, WireGuard
//     and Headscale so an admin is never locked out — and drops it from every other
//     source.
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

	trusted := trustedAdminSources() // loopback, Docker bridge, WireGuard, Headscale (v4)

	sb.WriteString("table inet motte_cf_only {\n")
	if len(v4) > 0 {
		sb.WriteString(BuildSet("cf_v4", "ipv4_addr", []string{"interval", "auto-merge"}, v4))
	}
	if len(v6) > 0 {
		sb.WriteString(BuildSet("cf_v6", "ipv6_addr", []string{"interval", "auto-merge"}, v6))
	}
	// Two chains, both priority -10 (before the main firewall):
	//   - input: host-destined web ports (a host-networked service, if any).
	//   - forward: Traefik's 80/443 are Docker-PUBLISHED, so that traffic is DNAT'd and
	//     FORWARDED to the container — it never reaches the input hook. Scope the forward
	//     rules to `ct status dnat` so only externally-published traffic is filtered and
	//     WireGuard / container-to-container forwarding is untouched.
	sb.WriteString(BuildChain("input", "filter", "input", -10, "accept", cfRules(v4, v6, trusted, "")))
	sb.WriteString(BuildChain("forward", "filter", "forward", -10, "accept", cfRules(v4, v6, trusted, "ct status dnat ")))
	sb.WriteString("}\n")
	return sb.String(), nil
}

// cfRules builds the accept-Cloudflare-and-trusted / drop-everyone-else rules for the web
// ports. prefix is prepended to each rule — "" for the input chain, "ct status dnat " for
// the forward chain (so it only matches externally-published, DNAT'd traffic).
func cfRules(v4, v6, trusted []string, prefix string) []string {
	rules := []string{
		"# Always-allowed local/VPN sources reach the web ports (never lock the admin out).",
		prefix + "ip saddr { " + strings.Join(trusted, ", ") + " } tcp dport { 80, 443 } accept",
		prefix + "ip6 saddr ::1/128 tcp dport { 80, 443 } accept",
		"# Cloudflare edge ranges — the only public source allowed to reach 80/443.",
	}
	if len(v4) > 0 {
		rules = append(rules, prefix+"ip saddr @cf_v4 tcp dport { 80, 443 } accept")
	}
	if len(v6) > 0 {
		rules = append(rules, prefix+"ip6 saddr @cf_v6 tcp dport { 80, 443 } accept")
	}
	rules = append(rules,
		"# Log (rate-limited) then drop 80/443 from every other source.",
		prefix+`tcp dport { 80, 443 } limit rate 5/minute log prefix "CF_ONLY_DROP: "`,
		prefix+"tcp dport { 80, 443 } drop",
	)
	return rules
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

// trustedAdminSources returns the CIDRs that keep reaching the web ports with Cloudflare-only on,
// so an admin can never be locked out of their own panel:
//   - loopback
//   - the Docker bridge (DOCKER_SUBNET) so Traefik keeps reaching the API
//   - the WireGuard range (WG_IP_RANGE) — admins on the WG VPN
//   - the Headscale/Tailscale overlay (HEADSCALE_IP_RANGE) — admins on the Tailnet
//
// The ranges come from the same env vars the rest of the stack uses; each has a sane
// fallback matching .env.example so a missing/garbled var can never drop a trusted source.
func trustedAdminSources() []string {
	out := []string{"127.0.0.0/8"}
	if c := validCIDROr(os.Getenv("DOCKER_SUBNET"), "172.18.0.0/24"); c != "" {
		out = append(out, c)
	}
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
