package nftables

import (
	"strings"

	"api/internal/database"
	"api/internal/helper"
)

// CloudflareOnlyTable optionally restricts inbound access to the web ports (80/443)
// to Cloudflare's edge ranges only — so nobody can bypass Cloudflare by hitting the
// server's raw IP. It is a SEPARATE, clearly-named table (inet wgadmin_cf_only),
// mirroring wgadmin_panel_access.
//
// Driven by the `web_cloudflare_only` setting:
//   - OFF (default): an EMPTY shell — 80/443 stay open to everyone.
//   - ON: an input-hook chain (priority -10, BEFORE the main firewall at 0) that
//     accepts 80/443 from Cloudflare — plus loopback, the Docker bridge, WireGuard
//     and Headscale so an admin is never locked out — and drops it from every other
//     source.
//
// Fail-open like panel-access: if disabled, or the Cloudflare list is somehow empty,
// it emits an empty table so it can NEVER drop all web traffic.
type CloudflareOnlyTable struct {
	db *database.DB
}

// NewCloudflareOnlyTable creates the Cloudflare-only table builder.
func NewCloudflareOnlyTable(db *database.DB) *CloudflareOnlyTable {
	return &CloudflareOnlyTable{db: db}
}

func (t *CloudflareOnlyTable) Name() string   { return "wgadmin_cf_only" }
func (t *CloudflareOnlyTable) Family() string { return "inet" }

// Priority orders this table's emission after panel-access (5); the chain hook
// priority (-10) is what actually orders kernel evaluation (before the main
// firewall at 0).
func (t *CloudflareOnlyTable) Priority() int { return 6 }

func (t *CloudflareOnlyTable) Build() (string, error) {
	var sb strings.Builder
	// Idempotent create/delete/define, mirroring the other tables.
	sb.WriteString("table inet wgadmin_cf_only\ndelete table inet wgadmin_cf_only\n\n")

	v4, v6 := splitCIDRs(helper.CloudflareCIDRs())

	// FAIL OPEN: never risk dropping all web access. If the toggle is off, or we have
	// no Cloudflare ranges to allow, emit an empty table (no filtering).
	if !t.restrictEnabled() || len(v4)+len(v6) == 0 {
		sb.WriteString("table inet wgadmin_cf_only {\n}\n")
		return sb.String(), nil
	}

	trusted := trustedPanelSources() // loopback, Docker bridge, WireGuard, Headscale (v4)

	sb.WriteString("table inet wgadmin_cf_only {\n")
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

// restrictEnabled reports whether 80/443 should be Cloudflare-only. True only when
// `web_cloudflare_only` is explicitly "on"; anything else (incl. missing / read
// error) is off, so the panel fails open.
func (t *CloudflareOnlyTable) restrictEnabled() bool {
	if t.db == nil {
		return false
	}
	var v string
	if err := t.db.QueryRow(`SELECT value FROM settings WHERE key = ? AND encrypted = 0`, "web_cloudflare_only").Scan(&v); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v), "on")
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
