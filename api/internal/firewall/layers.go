package firewall

import (
	"net/http"

	"api/internal/router"
)

// periodToInterval maps a ?period= value to a SQLite datetime modifier + a short label,
// matching the windows the logs/stats endpoint uses.
func periodToInterval(p string) (interval, label string) {
	switch p {
	case "hour":
		return "-1 hour", "1h"
	case "week":
		return "-7 days", "7d"
	case "month":
		return "-30 days", "30d"
	case "all":
		return "-100 years", "all"
	default:
		return "-1 day", "24h"
	}
}

// handleLayers returns the "blocked by layer" summary for a window: how much each
// enforcement layer (L3 firewall / DNS / L7 proxy) blocked, plus allowed traffic.
// GET /api/fw/layers?period=hour|day|week|month|all
func (s *Service) handleLayers(w http.ResponseWriter, r *http.Request) {
	interval, label := periodToInterval(r.URL.Query().Get("period"))

	l3 := s.L3BlockedWindow(interval) // sampled nftables packet drops
	l7 := s.L7BlockedWindow(interval) // sentinel proxy drops

	var dnsBlocked, dnsTotal, inboundAllowed int
	s.db.QueryRow(`SELECT COUNT(*) FROM logs WHERE logs_type='dns'
		AND logs_timestamp > datetime('now', ?)`, interval).Scan(&dnsTotal)
	s.db.QueryRow(`SELECT COUNT(*) FROM logs WHERE logs_type='dns'
		AND (logs_status LIKE '%BLOCK%' OR logs_status LIKE '%FILTER%')
		AND logs_timestamp > datetime('now', ?)`, interval).Scan(&dnsBlocked)
	// Inbound requests that were logged are the ones that got through (blocked L7
	// requests are silent-dropped and never logged), so this is "allowed at the edge".
	s.db.QueryRow(`SELECT COUNT(*) FROM logs WHERE logs_type='inbound'
		AND logs_timestamp > datetime('now', ?)`, interval).Scan(&inboundAllowed)

	blockedTotal := int(l3) + dnsBlocked + l7
	var pct float64
	if inboundAllowed+blockedTotal > 0 {
		pct = float64(inboundAllowed) / float64(inboundAllowed+blockedTotal) * 100
	}

	router.JSON(w, map[string]interface{}{
		"window":        label,
		"l3":            map[string]int64{"blocked": l3},
		"dns":           map[string]int{"blocked": dnsBlocked, "total": dnsTotal},
		"l7":            map[string]int{"blocked": l7},
		"allowed":       map[string]interface{}{"requests": inboundAllowed, "percent": pct},
		"total_blocked": blockedTotal,
	})
}
