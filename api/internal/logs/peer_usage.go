package logs

import (
	"net/http"
	"time"

	"api/internal/geolocation"
	"api/internal/router"
)

// PeerUsageDest is one destination's byte totals for a peer.
type PeerUsageDest struct {
	DestIP     string `json:"dest_ip"`
	Domain     string `json:"domain,omitempty"`
	Country    string `json:"country,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	BytesUp    int64  `json:"bytes_up"`
	BytesDown  int64  `json:"bytes_down"`
	BytesTotal int64  `json:"bytes_total"`
}

// PeerUsageBucket is one time-series point (hour bucket) of a peer's bytes.
type PeerUsageBucket struct {
	Time  string `json:"time"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	Total int64  `json:"total"`
}

// PeerUsageResponse is the per-peer destination breakdown.
type PeerUsageResponse struct {
	Peer         string            `json:"peer"`
	Period       string            `json:"period"`
	TotalUp      int64             `json:"total_up"`
	TotalDown    int64             `json:"total_down"`
	Destinations []PeerUsageDest   `json:"destinations"`
	Series       []PeerUsageBucket `json:"series"`
}

// periodSince maps a period string to a UTC cutoff time matching the
// hour-bucketed traffic_usage rows.
func periodSince(period string) time.Time {
	now := time.Now().UTC()
	switch period {
	case "hour":
		return now.Add(-time.Hour)
	case "week":
		return now.Add(-7 * 24 * time.Hour)
	case "month":
		return now.Add(-30 * 24 * time.Hour)
	default: // day
		return now.Add(-24 * time.Hour)
	}
}

// handleGetPeerUsage handles GET /api/logs/peer-usage?peer=<ip>&period=day
// It returns the top destinations by bytes for a single VPN peer, so the
// dashboard can break a peer's total traffic down by where it went.
func (s *Service) handleGetPeerUsage(w http.ResponseWriter, r *http.Request) {
	peer := r.URL.Query().Get("peer")
	if peer == "" {
		router.JSONError(w, "peer parameter required", http.StatusBadRequest)
		return
	}
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "day"
	}
	since := periodSince(period)

	rows, err := s.db.Query(`
		SELECT dest_ip,
		       COALESCE(MAX(protocol), '') AS protocol,
		       SUM(bytes_up)   AS up,
		       SUM(bytes_down) AS down
		FROM traffic_usage
		WHERE peer_ip = ? AND bucket >= ?
		GROUP BY dest_ip
		ORDER BY up + down DESC
		LIMIT 25
	`, peer, since)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	resp := PeerUsageResponse{Peer: peer, Period: period, Destinations: []PeerUsageDest{}, Series: []PeerUsageBucket{}}
	geoSvc := geolocation.GetService()

	for rows.Next() {
		var d PeerUsageDest
		if err := rows.Scan(&d.DestIP, &d.Protocol, &d.BytesUp, &d.BytesDown); err != nil {
			continue
		}
		d.BytesTotal = d.BytesUp + d.BytesDown
		resp.TotalUp += d.BytesUp
		resp.TotalDown += d.BytesDown

		// Best-effort domain from any outbound log row for this destination.
		var domain string
		if err := s.db.QueryRow(
			`SELECT logs_domain FROM logs WHERE logs_dest_ip = ? AND logs_domain IS NOT NULL AND logs_domain != '' LIMIT 1`,
			d.DestIP,
		).Scan(&domain); err == nil {
			d.Domain = domain
		}

		// Best-effort country enrichment.
		if geoSvc != nil && geoSvc.IsLookupAvailable() {
			if res, err := geoSvc.LookupIP(d.DestIP); err == nil && res != nil {
				d.Country = res.CountryCode
			}
		}

		resp.Destinations = append(resp.Destinations, d)
	}

	// Time series: bytes per hour bucket, for charting the peer's traffic.
	if sRows, err := s.db.Query(`
		SELECT bucket, SUM(bytes_up) AS up, SUM(bytes_down) AS down
		FROM traffic_usage
		WHERE peer_ip = ? AND bucket >= ?
		GROUP BY bucket
		ORDER BY bucket
	`, peer, since); err == nil {
		defer sRows.Close()
		for sRows.Next() {
			var bucket time.Time
			var up, down int64
			if err := sRows.Scan(&bucket, &up, &down); err != nil {
				continue
			}
			resp.Series = append(resp.Series, PeerUsageBucket{
				Time:  bucket.Format("01-02 15h"),
				Up:    up,
				Down:  down,
				Total: up + down,
			})
		}
	}

	router.JSON(w, resp)
}

// handleResetPeerUsage handles DELETE /api/logs/peer-usage?peer=<ip>
// Clears the byte rollup for one peer (or all peers if peer is omitted), so
// measurement effectively restarts from zero. In-flight flows keep their
// running counters, so only bytes transferred after the reset are counted.
func (s *Service) handleResetPeerUsage(w http.ResponseWriter, r *http.Request) {
	peer := r.URL.Query().Get("peer")
	var err error
	if peer == "" {
		_, err = s.db.Exec(`DELETE FROM traffic_usage`)
	} else {
		_, err = s.db.Exec(`DELETE FROM traffic_usage WHERE peer_ip = ?`, peer)
	}
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "ok"})
}
