package turbotunnels

import (
	"database/sql"

	"api/internal/database"
)

// ProxyStats summarizes proxy usage over the last 24h — overall (for the top
// stat cards) and per tunnel (keyed by the tunnel's username), for the
// per-tunnel summaries.
type ProxyStats struct {
	Window   string                 `json:"window"`
	Requests int                    `json:"requests"` // successful proxy connections
	Failed   int                    `json:"failed"`   // failed auth attempts
	Clients  int                    `json:"clients"`  // distinct source IPs
	TopDest  string                 `json:"topDest"`  // most-used destination host
	PerUser  map[string]TunnelStats `json:"perUser"`
}

// TunnelStats is one tunnel's usage summary.
type TunnelStats struct {
	Requests int    `json:"requests"`
	Failed   int    `json:"failed"`
	Clients  int    `json:"clients"`
	LastSeen string `json:"lastSeen"` // most recent activity (raw datetime, formatted by UI)
}

const proxyStatsWindow = "-24 hours"

// GetProxyStats aggregates the 'proxy' log rows written by the connection
// streamer into overall + per-tunnel usage. Returns an empty (zeroed) result if
// the DB is unavailable, so the UI degrades gracefully.
func GetProxyStats() ProxyStats {
	stats := ProxyStats{Window: "24h", PerUser: map[string]TunnelStats{}}
	db, err := database.GetDB()
	if err != nil {
		return stats
	}

	// Overall totals.
	db.QueryRow(`
		SELECT
			COALESCE(SUM(CASE WHEN logs_status = 'allowed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN logs_status = 'blocked' THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT logs_src_ip)
		FROM logs
		WHERE logs_type = 'proxy' AND logs_timestamp > datetime('now', ?)`,
		proxyStatsWindow).Scan(&stats.Requests, &stats.Failed, &stats.Clients)

	// Most-used destination (successful connections only).
	var topDest sql.NullString
	db.QueryRow(`
		SELECT logs_domain
		FROM logs
		WHERE logs_type = 'proxy' AND logs_status = 'allowed'
		  AND logs_domain != '' AND logs_timestamp > datetime('now', ?)
		GROUP BY logs_domain ORDER BY COUNT(*) DESC LIMIT 1`,
		proxyStatsWindow).Scan(&topDest)
	stats.TopDest = topDest.String

	// Per-tunnel (per-username) breakdown.
	rows, err := db.Query(`
		SELECT
			COALESCE(logs_service, ''),
			COALESCE(SUM(CASE WHEN logs_status = 'allowed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN logs_status = 'blocked' THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT logs_src_ip),
			MAX(logs_timestamp)
		FROM logs
		WHERE logs_type = 'proxy' AND logs_timestamp > datetime('now', ?)
		GROUP BY logs_service`,
		proxyStatsWindow)
	if err != nil {
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var user string
		var lastSeen sql.NullString
		var t TunnelStats
		if err := rows.Scan(&user, &t.Requests, &t.Failed, &t.Clients, &lastSeen); err != nil {
			continue
		}
		if user == "" {
			continue
		}
		t.LastSeen = lastSeen.String
		stats.PerUser[user] = t
	}
	return stats
}
