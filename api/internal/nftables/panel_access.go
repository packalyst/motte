package nftables

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"api/internal/database"
)

// PanelAccessTable optionally restricts inbound access to the panel's OWN API port
// (API_PORT) to trusted sources only. It is a SEPARATE, clearly-named table
// (inet wgadmin_panel_access) so it is obvious in `nft list ruleset` what it does.
//
// Why a dedicated table (not a rule in wgadmin_firewall): each concern here is its own
// registered table (wgadmin_firewall, wgadmin_vpn_acl, ...). This one owns exactly one
// policy — "who may reach the panel API directly" — so it can be reasoned about, toggled,
// and inspected on its own.
//
// Behaviour, driven by the `api_direct_access` setting:
//   - ON  (default): the table is an EMPTY shell — the panel API stays reachable by
//     direct IP. This is REQUIRED before a domain is configured (IP is the only way in).
//   - OFF: an input-hook chain (priority -10, BEFORE the main firewall at 0) drops the
//     API port from the public internet, while still accepting it from loopback, the
//     Docker bridge (so Traefik keeps proxying the panel) and the WireGuard subnet (so a
//     VPN admin always has a way back in). All real traffic then arrives via the domain
//     through Traefik, where VPN-only / rate-limit / ban-list already apply.
//
// Composition note: the main firewall's input chain is `policy drop` and accepts the API
// port via @allowed_tcp_ports. This table cannot create an accept that overrides that
// (accept is not terminal across base chains) — it only ADDS a drop for the untrusted
// subset, which IS terminal. Trusted traffic is left to the firewall's normal accept.
type PanelAccessTable struct {
	db *database.DB
}

// NewPanelAccessTable creates the panel-access table builder.
func NewPanelAccessTable(db *database.DB) *PanelAccessTable { return &PanelAccessTable{db: db} }

func (t *PanelAccessTable) Name() string   { return "wgadmin_panel_access" }
func (t *PanelAccessTable) Family() string { return "inet" }

// Priority orders this table's emission in the combined script. It runs before the main
// firewall (10) so its base chain also sits earlier; the chain hook priority (-10) is what
// actually orders kernel evaluation.
func (t *PanelAccessTable) Priority() int { return 5 }

func (t *PanelAccessTable) Build() (string, error) {
	var sb strings.Builder
	// Idempotent create/delete/define, mirroring the other tables.
	sb.WriteString("table inet wgadmin_panel_access\ndelete table inet wgadmin_panel_access\n\n")

	restrict := t.restrictEnabled()
	port, portOK := apiPort()
	trusted := trustedPanelSources()

	// FAIL OPEN: if direct access is allowed, or we can't safely determine the port or the
	// trusted sources, emit an empty table (no filtering) — we must NEVER risk locking the
	// panel out of its own management plane by dropping traffic we can't classify.
	if !restrict || !portOK || len(trusted) == 0 {
		sb.WriteString("table inet wgadmin_panel_access {\n}\n")
		return sb.String(), nil
	}

	rules := []string{
		"# Trusted sources reach the panel API: loopback, Docker bridge (Traefik), WireGuard admin",
		fmt.Sprintf("ip saddr { %s } tcp dport %d accept", strings.Join(trusted, ", "), port),
		"",
		"# Log (rate-limited) then drop the API port from every other source (the public internet).",
		"# Reach the panel via your domain instead — that path keeps VPN-only / rate-limit / bans.",
		fmt.Sprintf(`tcp dport %d limit rate 5/minute log prefix "PANEL_ACCESS_DROP: "`, port),
		fmt.Sprintf("tcp dport %d drop", port),
	}

	sb.WriteString("table inet wgadmin_panel_access {\n")
	sb.WriteString(BuildChain("input", "filter", "input", -10, "accept", rules))
	sb.WriteString("}\n")
	return sb.String(), nil
}

// restrictEnabled reports whether the API port should be closed to the public. It is only
// true when the `api_direct_access` setting is explicitly "off"; a missing setting means
// direct access is allowed (the safe default for a fresh, domain-less install).
func (t *PanelAccessTable) restrictEnabled() bool {
	if t.db == nil {
		return false
	}
	var v string
	err := t.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, "api_direct_access").Scan(&v)
	if err != nil {
		if err != sql.ErrNoRows {
			return false // on any read error, fail open (don't restrict)
		}
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v), "off")
}

// apiPort returns the validated API_PORT (1–65535).
func apiPort() (int, bool) {
	p, err := strconv.Atoi(strings.TrimSpace(os.Getenv("API_PORT")))
	if err != nil || p < 1 || p > 65535 {
		return 0, false
	}
	return p, true
}

// trustedPanelSources returns the CIDRs always allowed to reach the API port even when
// direct access is off: loopback, the Docker bridge (so Traefik keeps reaching the API),
// and the WireGuard range (so a VPN admin can never be locked out). Env values are
// validated as CIDRs; each falls back to a sane default so a missing/garbled env var can
// never drop the trusted source that keeps the panel reachable.
func trustedPanelSources() []string {
	out := []string{"127.0.0.0/8"}
	if c := validCIDROr(os.Getenv("DOCKER_SUBNET"), "172.18.0.0/24"); c != "" {
		out = append(out, c)
	}
	if c := validCIDROr(os.Getenv("WG_IP_RANGE"), "10.8.0.0/16"); c != "" {
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
