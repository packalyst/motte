package geolocation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ASNMatch is one provider in an ASN search result.
type ASNMatch struct {
	ASN    uint32 `json:"asn"`
	Name   string `json:"name"`
	Ranges int    `json:"ranges"` // approximate IPv4 range/CIDR count
}

// SearchASN finds providers whose name contains the query, or whose AS number
// equals it. One bounded linear pass over the loaded table (no persistent index,
// so no steady-state memory); called only interactively while adding a rule.
// Results are the top `limit` by range count. IPv6-only ASNs are ignored.
func (s *Service) SearchASN(query string, limit int) []ASNMatch {
	s.mu.RLock()
	db := s.asnDB
	s.mu.RUnlock()
	if db == nil {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}

	// A purely numeric query (optionally "AS1234") also matches that AS number.
	var qNum uint32
	var isNum bool
	if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(q), "AS"), 10, 32); err == nil {
		qNum, isNum = uint32(n), true
	}

	db.mu.RLock()
	rows := db.rows
	db.mu.RUnlock()

	agg := make(map[uint32]*ASNMatch)
	for i := range rows {
		v := rows[i].val
		if v.asn == 0 {
			continue
		}
		if _, ok := v4From16(rows[i].lo); !ok {
			continue // IPv4-only firewall
		}
		if !((isNum && v.asn == qNum) || strings.Contains(strings.ToLower(v.name), q)) {
			continue
		}
		if m := agg[v.asn]; m != nil {
			m.Ranges++
		} else {
			agg[v.asn] = &ASNMatch{ASN: v.asn, Name: v.name, Ranges: 1}
		}
	}

	out := make([]ASNMatch, 0, len(agg))
	for _, m := range agg {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ranges != out[j].Ranges {
			return out[i].Ranges > out[j].Ranges
		}
		return out[i].ASN < out[j].ASN
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// CacheASNZones expands an ASN into its IPv4 CIDRs (from the loaded ASN DB) and
// stores them in asn_zones_cache, so the firewall builder can join them cheaply.
// Returns the number of CIDRs cached. Caches an empty string (0 CIDRs) when the
// ASN DB isn't loaded or the ASN owns no IPv4 ranges — the caller can surface
// "0 ranges" rather than silently succeeding.
func (s *Service) CacheASNZones(asn uint32) (int, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not available")
	}
	cidrs := s.ASNRangesV4(asn)
	_, err := s.db.Exec(`
		INSERT INTO asn_zones_cache (asn, cidrs, updated_at) VALUES (?, ?, datetime('now'))
		ON CONFLICT(asn) DO UPDATE SET cidrs = excluded.cidrs, updated_at = datetime('now')`,
		asn, strings.Join(cidrs, ","))
	if err != nil {
		return 0, err
	}
	return len(cidrs), nil
}

// GetBlockedASNCIDRs returns the IPv4 CIDRs of every enabled, blocking ASN entry,
// joined with its cached ranges. outboundOnly restricts to direction='both'
// entries (the ones that also block outbound). Mirrors GetAllBlockedCIDRs for
// countries.
func (s *Service) GetBlockedASNCIDRs(outboundOnly bool) ([]string, error) {
	return s.asnCIDRsByAction("block", outboundOnly)
}

// GetAllowedASNCIDRs returns the IPv4 CIDRs of every enabled, allowing ASN entry.
// Allow is source-only (no outbound direction), so there is no outbound variant.
func (s *Service) GetAllowedASNCIDRs() ([]string, error) {
	return s.asnCIDRsByAction("allow", false)
}

// asnCIDRsByAction joins ASN entries of the given action with their cached ranges.
// Keeping block and allow on one query (parameterized action) guarantees an entry
// can only ever feed the matching set — a block never leaks into the allow set or
// vice-versa.
func (s *Service) asnCIDRsByAction(action string, outboundOnly bool) ([]string, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	query := `SELECT c.cidrs FROM asn_zones_cache c
		INNER JOIN firewall_entries f ON c.asn = CAST(f.value AS INTEGER)
		WHERE f.entry_type = 'asn' AND f.action = ? AND f.enabled = 1`
	if outboundOnly {
		query += ` AND f.direction = 'both'`
	}

	rows, err := s.db.Query(query, action)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var cidrs string
		if err := rows.Scan(&cidrs); err != nil {
			continue
		}
		for _, c := range strings.Split(cidrs, ",") {
			if c = strings.TrimSpace(c); c != "" {
				out = append(out, c)
			}
		}
	}
	return out, rows.Err()
}
