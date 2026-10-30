package firewall

import (
	"net/http"
	"strings"

	"api/internal/helper"
)

// AllBlockedCIDRs assembles every actively-blocked SOURCE: enabled, unexpired ip/range
// firewall entries (inbound/both) plus the expanded country + ASN CIDRs. This is the same
// data that feeds the nftables blocked sets, exposed so the Traefik "sentinel" plugin can
// enforce the same blocks on Cloudflare-proxied (L7) traffic — where nftables (L3) only
// ever sees the Cloudflare edge IP, not the real visitor.
func (s *Service) AllBlockedCIDRs() []string {
	out := []string{}
	rows, err := s.db.Query(`SELECT value FROM firewall_entries
		WHERE entry_type IN ('ip','range') AND action = 'block' AND enabled = 1
		  AND direction IN ('inbound','both')
		  AND (expires_at IS NULL OR expires_at > datetime('now'))`)
	if err == nil {
		for rows.Next() {
			var v string
			if rows.Scan(&v) == nil {
				if v = strings.TrimSpace(v); v != "" {
					out = append(out, v)
				}
			}
		}
		rows.Close()
	}
	if s.geo != nil {
		if c, err := s.geo.GetAllBlockedCIDRs(false); err == nil {
			out = append(out, c...)
		}
		if c, err := s.geo.GetBlockedASNCIDRs(false); err == nil {
			out = append(out, c...)
		}
	}
	return out
}

// ExplicitBlockedCIDRs returns ONLY the operator/escalation ip+range blocks (enabled,
// unexpired, inbound). It deliberately excludes the expanded country/ASN CIDRs — those
// are millions of entries meant for the panel's own nftables sets, far too large to push
// down to a member machine. This is what the fleet "push panel blocks" command ships to an
// agent so a host benefits from the specific IPs the panel already knows are hostile.
//
// A read error is returned, never an empty list: a push replaces the machine's list, so an
// empty one caused by a database hiccup would silently unblock everything.
func (s *Service) ExplicitBlockedCIDRs() ([]string, error) {
	out := []string{}
	rows, err := s.db.Query(`SELECT value FROM firewall_entries
		WHERE entry_type IN ('ip','range') AND action = 'block' AND enabled = 1
		  AND direction IN ('inbound','both')
		  AND (expires_at IS NULL OR expires_at > datetime('now'))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out, rows.Err()
}

// HandleInternalBlocklist serves the block list as plain text (one CIDR/IP per line) for
// the Traefik sentinel plugin to fetch over the internal Docker network.
//
// Unauthenticated by design — it is internal-only (the api port isn't internet-exposed),
// not routed by Traefik, and the data (a list of blocked IPs) is not a secret. Only Traefik's own
// address may fetch it (internalCallerAllowed), so any other source or forged edge headers are
// refused.
func (s *Service) HandleInternalBlocklist(w http.ResponseWriter, r *http.Request) {
	if !internalCallerAllowed(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	list := s.AllBlockedCIDRs()
	w.Write([]byte(strings.Join(list, "\n")))
	if len(list) > 0 {
		w.Write([]byte("\n"))
	}
}

// HandleInternalCloudflare serves Cloudflare's current edge ranges (one CIDR per line), the
// panel's live list (helper.CloudflareCIDRs, refreshed daily), for the Traefik sentinel plugin: it
// is the one list every part of the stack decides "came through Cloudflare" by. Internal-only.
func (s *Service) HandleInternalCloudflare(w http.ResponseWriter, r *http.Request) {
	if !internalCallerAllowed(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(strings.Join(helper.CloudflareCIDRs(), "\n") + "\n"))
}
