package firewall

import (
	"sync"
	"time"

	"api/internal/ws"
)

// The Overview security widgets (verdict, worst-offender, blocked-by-layer, public
// visitors) used to each poll every 30s. Instead this summary is pushed on the WS
// stats stream. The broadcast fires on a fast tick, so the computation is cached for
// 30s — it runs at most once per 30s regardless of how many clients are connected.

var dashSec struct {
	mu   sync.Mutex
	at   time.Time
	data *ws.SecurityStats
}

// DashboardSecurity returns the cached last-hour security summary for the broadcast.
func (s *Service) DashboardSecurity() *ws.SecurityStats {
	dashSec.mu.Lock()
	defer dashSec.mu.Unlock()
	if dashSec.data != nil && time.Since(dashSec.at) < 30*time.Second {
		return dashSec.data
	}
	dashSec.data = &ws.SecurityStats{
		Overview: s.securityOverviewData(),
		Layers:   s.layersData("-1 hour", "1h"),
		Visitors: s.visitorsData("-1 hour"),
	}
	dashSec.at = time.Now()
	return dashSec.data
}

func (s *Service) visitorsData(interval string) map[string]interface{} {
	var unique, countries int
	s.db.QueryRow(`SELECT COUNT(DISTINCT logs_src_ip), COUNT(DISTINCT NULLIF(logs_src_country, ''))
		FROM logs WHERE logs_type = 'inbound' AND logs_src_ip != ''
		  AND logs_timestamp > datetime('now', ?)`, interval).Scan(&unique, &countries)
	return map[string]interface{}{"unique_visitors": unique, "countries": countries}
}
