package firewall

import (
	"database/sql"
	"net/http"

	"api/internal/router"
)

// Thresholds that map raw block counts to the calm / elevated / under-attack
// status light. Tuned for a personal / small-team panel.
const (
	elevatedBlocksPerHour    = 20
	underAttackBlocksPerHour = 100
	spikeMinBlocks           = 30 // ignore spikes below this (noise)
	spikeMultiplier          = 3  // this-hour ≥ N× last-hour ⇒ spike
)

// topAttacker is the single worst source IP this hour, enriched with owner +
// reputation when the geo service is available.
type topAttacker struct {
	IP         string      `json:"ip"`
	Count      int         `json:"count"`
	Country    string      `json:"country,omitempty"`
	Owner      string      `json:"owner,omitempty"`
	Reputation interface{} `json:"reputation,omitempty"`
}

type securityOverview struct {
	Window      string       `json:"window"`
	Blocked     int          `json:"blocked"`      // last hour
	BlockedPrev int          `json:"blocked_prev"` // the hour before (trend)
	Attackers   int          `json:"attackers"`    // distinct source IPs, last hour
	Countries   int          `json:"countries"`    // distinct source countries, last hour
	AutoBans    int          `json:"auto_bans"`    // active temporary bans
	TopAttacker *topAttacker `json:"top_attacker"` // may be nil
	Status      string       `json:"status"`       // calm | elevated | under_attack
}

// handleSecurityOverview returns a plain-language security summary for the last
// hour: how much was blocked, from where, the worst offender, and a single
// status light. Everything is derived from data the panel already stores.
func (s *Service) handleSecurityOverview(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, s.securityOverviewData())
}

// securityOverviewData computes the last-hour security summary (also reused by the
// WebSocket dashboard-security broadcast, so it isn't re-fetched per HTTP poll).
func (s *Service) securityOverviewData() securityOverview {
	out := securityOverview{Window: "1h", Status: "calm"}

	// Blocks this hour and the hour before (for spike detection).
	_ = s.db.QueryRow(`SELECT
		SUM(CASE WHEN logs_timestamp > datetime('now','-1 hour') THEN 1 ELSE 0 END),
		SUM(CASE WHEN logs_timestamp <= datetime('now','-1 hour')
		          AND logs_timestamp > datetime('now','-2 hour') THEN 1 ELSE 0 END)
		FROM logs WHERE logs_type = 'fw'
		  AND logs_timestamp > datetime('now','-2 hour')`).Scan(&out.Blocked, &out.BlockedPrev)

	// Distinct attackers + countries this hour.
	_ = s.db.QueryRow(`SELECT
		COUNT(DISTINCT logs_src_ip),
		COUNT(DISTINCT NULLIF(logs_src_country, ''))
		FROM logs WHERE logs_type = 'fw'
		  AND logs_timestamp > datetime('now','-1 hour')`).Scan(&out.Attackers, &out.Countries)

	// Active temporary (fail2ban-style) auto-bans — permanent manual blocks have
	// no expiry, so an expiry marks an automatic ban.
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries
		WHERE entry_type IN ('ip','range') AND action = 'block' AND enabled = 1
		  AND expires_at IS NOT NULL AND expires_at > datetime('now')`).Scan(&out.AutoBans)

	// Worst single offender this hour. MAX() keeps logs_src_country a proper
	// aggregate (a given IP maps to one country, so any row's value is correct).
	var ip, country sql.NullString
	var count int
	err := s.db.QueryRow(`SELECT logs_src_ip, MAX(logs_src_country), COUNT(*) c
		FROM logs WHERE logs_type = 'fw'
		  AND logs_timestamp > datetime('now','-1 hour')
		GROUP BY logs_src_ip ORDER BY c DESC LIMIT 1`).Scan(&ip, &country, &count)
	if err == nil && ip.Valid && ip.String != "" {
		ta := &topAttacker{IP: ip.String, Count: count, Country: country.String}
		// Enrich with owner + reputation when the geo service is available.
		if s.geo != nil {
			if res, gerr := s.geo.LookupIP(ip.String); gerr == nil && res != nil {
				ta.Owner = res.ASName
				ta.Reputation = res.Reputation
				if ta.Country == "" {
					ta.Country = res.CountryCode
				}
			}
		}
		out.TopAttacker = ta
	}

	out.Status = classifyStatus(out.Blocked, out.BlockedPrev)
	return out
}

// classifyStatus turns block counts into the traffic-light status.
func classifyStatus(blocked, prev int) string {
	spike := prev > 0 && blocked >= prev*spikeMultiplier && blocked >= spikeMinBlocks
	switch {
	case blocked >= underAttackBlocksPerHour || spike:
		return "under_attack"
	case blocked >= elevatedBlocksPerHour:
		return "elevated"
	default:
		return "calm"
	}
}
