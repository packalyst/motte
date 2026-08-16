package firewall

import (
	"net/http"
	"strings"
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

// HandleInternalBlocklist serves the block list as plain text (one CIDR/IP per line) for
// the Traefik sentinel plugin to fetch over the internal Docker network.
//
// Unauthenticated by design — it is internal-only (the api port isn't internet-exposed),
// not routed by Traefik, and the data (a list of blocked IPs) is not a secret. As a guard
// it REFUSES any request that carries proxy/edge headers (CF-Connecting-IP / X-Forwarded-For
// / X-Real-IP): those only appear on requests that came through the public edge, so the
// endpoint answers direct internal calls only.
func (s *Service) HandleInternalBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("CF-Connecting-IP") != "" ||
		r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Real-IP") != "" {
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
