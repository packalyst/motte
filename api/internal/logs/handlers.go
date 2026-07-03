package logs

import (
	"encoding/json"
	"net/http"

	"api/internal/database"
	"api/internal/router"
)

// LogsQuery represents query parameters for logs
type LogsQuery struct {
	Type   string `json:"type"`   // outbound, inbound, dns, or empty for all
	Limit  int    `json:"limit"`  // default 100
	Offset int    `json:"offset"` // for pagination
	Search string `json:"search"` // general search (domain, src_ip, dest_ip)
	Status string `json:"status"` // filter by status
}

// LogsResponse represents the API response
type LogsResponse struct {
	Logs     []LogEntry      `json:"logs"`
	Total    int             `json:"total"`
	Types    []LogTypeInfo   `json:"types"`
	Statuses []LogStatusInfo `json:"statuses"`
}

// StatsQuery represents query parameters for stats
type StatsQuery struct {
	Type   string `json:"type"`   // outbound, inbound, dns
	Period string `json:"period"` // hour, day, week
}

// StatsResponse represents aggregated stats for the Analytics dashboard.
// Some fields only populate for a specific `type=` filter (see comments).
type StatsResponse struct {
	// Universal (populated for every type)
	TotalCount     int           `json:"total_count"`
	PreviousTotal  int           `json:"previous_total"`  // same-length prior window, for trend arrows
	UniqueVisitors int           `json:"unique_visitors"` // COUNT DISTINCT logs_src_ip
	TotalBytes     int64         `json:"total_bytes"`
	TimeSeries     []Bucket      `json:"time_series"`
	TopClients     []ClientStat  `json:"top_clients"`
	TopCountries   []CountryStat `json:"top_countries"`   // src for inbound/dns/fw, dest for outbound

	// Inbound-specific (Traefik)
	TopDomains []DomainStat  `json:"top_domains,omitempty"`
	TopPaths   []PathStat    `json:"top_paths,omitempty"`
	HTTPStatus []StatusCount `json:"http_status,omitempty"` // 2xx/3xx/4xx/5xx buckets

	// DNS-specific (AdGuard)
	StatusCounts []StatusCount `json:"status_counts,omitempty"` // NOERROR/NXDOMAIN/BLOCK etc
	QueryTypes   []StatusCount `json:"query_types,omitempty"`   // A/AAAA/CNAME/MX
	CachedCount  int           `json:"cached_count,omitempty"`
	BlockedCount int           `json:"blocked_count,omitempty"`
	TopBlocked   []DomainStat  `json:"top_blocked,omitempty"`

	// Outbound-specific
	Protocols  []StatusCount `json:"protocols,omitempty"` // TCP/UDP mix
	TopDestIPs []ClientStat  `json:"top_dest_ips,omitempty"`

	// Firewall-specific
	TopDestPorts []StatusCount `json:"top_dest_ports,omitempty"` // ports being probed
	TopRules     []StatusCount `json:"top_rules,omitempty"`      // rules that fired most
}

// Bucket represents one time-series data point.
type Bucket struct {
	Time  string `json:"time"`
	Count int    `json:"count"`
	Bytes int64  `json:"bytes,omitempty"`
}

// PathStat represents URL path statistics.
type PathStat struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// DomainStat represents domain statistics
type DomainStat struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// ClientStat represents client statistics
type ClientStat struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// CountryStat represents country statistics
type CountryStat struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// StatusCount represents status counts
type StatusCount struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

// handleGetLogs handles GET /api/logs
func (s *Service) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	p := router.ParsePagination(r, 100)
	query := LogsQuery{
		Type:   r.URL.Query().Get("type"),
		Search: r.URL.Query().Get("search"),
		Status: r.URL.Query().Get("status"),
		Limit:  p.Limit,
		Offset: p.Offset,
	}

	// Build query
	baseQuery := `SELECT
		l.logs_id, l.logs_timestamp, l.logs_type, l.logs_src_ip,
		COALESCE(c.name, '') as logs_src_client_name,
		COALESCE(l.logs_src_country, '') as logs_src_country,
		COALESCE(l.logs_dest_ip, '') as logs_dest_ip,
		COALESCE(l.logs_dest_port, 0) as logs_dest_port,
		COALESCE(l.logs_dest_country, '') as logs_dest_country,
		COALESCE(l.logs_domain, '') as logs_domain,
		COALESCE(l.logs_protocol, '') as logs_protocol,
		COALESCE(l.logs_status, '') as logs_status,
		COALESCE(l.logs_duration, 0) as logs_duration,
		COALESCE(l.logs_bytes, 0) as logs_bytes,
		COALESCE(l.logs_cached, 0) as logs_cached,
		COALESCE(l.logs_method, '') as logs_method,
		COALESCE(l.logs_path, '') as logs_path,
		COALESCE(l.logs_router, '') as logs_router,
		COALESCE(l.logs_service, '') as logs_service,
		COALESCE(l.logs_query_type, '') as logs_query_type,
		COALESCE(l.logs_upstream, '') as logs_upstream,
		COALESCE(l.logs_rule, '') as logs_rule
	FROM logs l
	LEFT JOIN vpn_clients c ON l.logs_src_ip = c.ip
	WHERE 1=1`

	countQuery := "SELECT COUNT(*) FROM logs WHERE 1=1"
	args := []interface{}{}

	if query.Type != "" {
		baseQuery += " AND l.logs_type = ?"
		countQuery += " AND logs_type = ?"
		args = append(args, query.Type)
	}

	if query.Search != "" {
		searchPattern := "%" + database.EscapeLikePattern(query.Search) + "%"
		baseQuery += " AND (l.logs_domain LIKE ? OR l.logs_src_ip LIKE ? OR l.logs_dest_ip LIKE ?)"
		countQuery += " AND (logs_domain LIKE ? OR logs_src_ip LIKE ? OR logs_dest_ip LIKE ?)"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	if query.Status != "" {
		baseQuery += " AND l.logs_status = ?"
		countQuery += " AND logs_status = ?"
		args = append(args, query.Status)
	}

	// Get total count
	var total int
	s.db.QueryRow(countQuery, args...).Scan(&total)

	// Add ordering and pagination
	baseQuery += " ORDER BY l.logs_timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, query.Limit, query.Offset)

	rows, err := s.db.Query(baseQuery, args...)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	logs := []LogEntry{}
	for rows.Next() {
		var entry LogEntry
		err := rows.Scan(
			&entry.ID, &entry.Timestamp, &entry.Type, &entry.SrcIP,
			&entry.SrcClientName, &entry.SrcCountry, &entry.DestIP, &entry.DestPort, &entry.DestCountry,
			&entry.Domain, &entry.Protocol, &entry.Status, &entry.Duration,
			&entry.Bytes, &entry.Cached, &entry.Method, &entry.Path,
			&entry.Router, &entry.Service, &entry.QueryType, &entry.Upstream,
			&entry.Rule,
		)
		if err != nil {
			continue
		}
		logs = append(logs, entry)
	}

	response := LogsResponse{
		Logs:     logs,
		Total:    total,
		Types:    AllLogTypes,
		Statuses: AllLogStatuses,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetStats handles GET /api/logs/stats.
// Params: type=inbound|dns|outbound|fw (or empty for all), period=hour|day|week
// Returns aggregated statistics for the Analytics dashboard.
func (s *Service) handleGetStats(w http.ResponseWriter, r *http.Request) {
	logType := r.URL.Query().Get("type")
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "day"
	}

	// Current window + previous window (for trend comparison)
	var interval, prevStart, bucketFmt string
	switch period {
	case "hour":
		interval = "-1 hour"
		prevStart = "-2 hours"
		bucketFmt = "%Y-%m-%d %H:%M:00" // per-minute for 1h
	case "week":
		interval = "-7 days"
		prevStart = "-14 days"
		bucketFmt = "%Y-%m-%d" // per-day for 1w
	default: // day
		interval = "-1 day"
		prevStart = "-2 days"
		bucketFmt = "%Y-%m-%d %H:00:00" // hourly for 1d
	}

	typeFilter := ""
	args := []interface{}{interval}
	if logType != "" {
		typeFilter = " AND logs_type = ?"
		args = append(args, logType)
	}

	stats := StatsResponse{}

	// ── UNIVERSAL (all types) ─────────────────────────────────────────

	// Total count in current window
	s.db.QueryRow(`
		SELECT COUNT(*) FROM logs
		WHERE logs_timestamp > datetime('now', ?)`+typeFilter, args...).Scan(&stats.TotalCount)

	// Previous-period total (for % change arrow)
	prevArgs := []interface{}{prevStart, interval}
	prevFilter := ""
	if logType != "" {
		prevFilter = " AND logs_type = ?"
		prevArgs = append(prevArgs, logType)
	}
	s.db.QueryRow(`
		SELECT COUNT(*) FROM logs
		WHERE logs_timestamp > datetime('now', ?)
		  AND logs_timestamp <= datetime('now', ?)`+prevFilter,
		prevArgs...,
	).Scan(&stats.PreviousTotal)

	// Unique visitors
	s.db.QueryRow(`
		SELECT COUNT(DISTINCT logs_src_ip) FROM logs
		WHERE logs_timestamp > datetime('now', ?)
		  AND logs_src_ip != ''`+typeFilter, args...).Scan(&stats.UniqueVisitors)

	// Total bytes (may be 0 for types that don't track it)
	s.db.QueryRow(`
		SELECT COALESCE(SUM(logs_bytes), 0) FROM logs
		WHERE logs_timestamp > datetime('now', ?)`+typeFilter, args...).Scan(&stats.TotalBytes)

	// Time series — buckets sized to the period
	tsArgs := append([]interface{}{bucketFmt}, args...)
	tsRows, _ := s.db.Query(`
		SELECT strftime(?, logs_timestamp) AS bucket,
		       COUNT(*) AS cnt,
		       COALESCE(SUM(logs_bytes), 0) AS bytes
		FROM logs
		WHERE logs_timestamp > datetime('now', ?)`+typeFilter+`
		GROUP BY bucket
		ORDER BY bucket
	`, tsArgs...)
	if tsRows != nil {
		defer tsRows.Close()
		for tsRows.Next() {
			var b Bucket
			tsRows.Scan(&b.Time, &b.Count, &b.Bytes)
			stats.TimeSeries = append(stats.TimeSeries, b)
		}
	}

	// Top clients (source IP + country)
	clientRows, _ := s.db.Query(`
		SELECT logs_src_ip, COALESCE(logs_src_country, ''), COUNT(*) as cnt
		FROM logs
		WHERE logs_timestamp > datetime('now', ?)
		  AND logs_src_ip != ''`+typeFilter+`
		GROUP BY logs_src_ip
		ORDER BY cnt DESC
		LIMIT 10
	`, args...)
	if clientRows != nil {
		defer clientRows.Close()
		for clientRows.Next() {
			var stat ClientStat
			clientRows.Scan(&stat.IP, &stat.Country, &stat.Count)
			stats.TopClients = append(stats.TopClients, stat)
		}
	}

	// Top countries — src for inbound/dns/fw, dest for outbound
	countryCol := "logs_src_country"
	if logType == "outbound" {
		countryCol = "logs_dest_country"
	}
	countryRows, _ := s.db.Query(`
		SELECT `+countryCol+`, COUNT(*) as cnt
		FROM logs
		WHERE logs_timestamp > datetime('now', ?)
		  AND `+countryCol+` IS NOT NULL
		  AND `+countryCol+` != ''`+typeFilter+`
		GROUP BY `+countryCol+`
		ORDER BY cnt DESC
		LIMIT 10
	`, args...)
	if countryRows != nil {
		defer countryRows.Close()
		for countryRows.Next() {
			var stat CountryStat
			countryRows.Scan(&stat.Country, &stat.Count)
			stats.TopCountries = append(stats.TopCountries, stat)
		}
	}

	// ── INBOUND (Traefik) ─────────────────────────────────────────────

	if logType == "inbound" || logType == "" {
		// Top domains
		domainRows, _ := s.db.Query(`
			SELECT logs_domain, COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_domain != ''
			  AND logs_type = 'inbound'
			GROUP BY logs_domain ORDER BY cnt DESC LIMIT 10
		`, interval)
		if domainRows != nil {
			defer domainRows.Close()
			for domainRows.Next() {
				var stat DomainStat
				domainRows.Scan(&stat.Domain, &stat.Count)
				stats.TopDomains = append(stats.TopDomains, stat)
			}
		}

		// Top paths
		pathRows, _ := s.db.Query(`
			SELECT logs_path, COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'inbound'
			  AND logs_path != ''
			GROUP BY logs_path ORDER BY cnt DESC LIMIT 10
		`, interval)
		if pathRows != nil {
			defer pathRows.Close()
			for pathRows.Next() {
				var stat PathStat
				pathRows.Scan(&stat.Path, &stat.Count)
				stats.TopPaths = append(stats.TopPaths, stat)
			}
		}

		// HTTP status buckets (2xx/3xx/4xx/5xx)
		httpRows, _ := s.db.Query(`
			SELECT CASE
				WHEN CAST(logs_status AS INTEGER) BETWEEN 200 AND 299 THEN '2xx'
				WHEN CAST(logs_status AS INTEGER) BETWEEN 300 AND 399 THEN '3xx'
				WHEN CAST(logs_status AS INTEGER) BETWEEN 400 AND 499 THEN '4xx'
				WHEN CAST(logs_status AS INTEGER) BETWEEN 500 AND 599 THEN '5xx'
				ELSE 'other'
			END AS bucket, COUNT(*) as cnt
			FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'inbound'
			  AND logs_status != ''
			GROUP BY bucket ORDER BY bucket
		`, interval)
		if httpRows != nil {
			defer httpRows.Close()
			for httpRows.Next() {
				var stat StatusCount
				httpRows.Scan(&stat.Status, &stat.Count)
				stats.HTTPStatus = append(stats.HTTPStatus, stat)
			}
		}
	}

	// ── DNS (AdGuard) ─────────────────────────────────────────────────

	if logType == "dns" || logType == "" {
		// Native status counts (NOERROR/NXDOMAIN/BLOCK…)
		statusRows, _ := s.db.Query(`
			SELECT logs_status, COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'dns'
			  AND logs_status != ''
			GROUP BY logs_status ORDER BY cnt DESC
		`, interval)
		if statusRows != nil {
			defer statusRows.Close()
			for statusRows.Next() {
				var stat StatusCount
				statusRows.Scan(&stat.Status, &stat.Count)
				stats.StatusCounts = append(stats.StatusCounts, stat)
			}
		}

		// Query types (A/AAAA/CNAME/…)
		qtRows, _ := s.db.Query(`
			SELECT logs_query_type, COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'dns'
			  AND logs_query_type != ''
			GROUP BY logs_query_type ORDER BY cnt DESC LIMIT 10
		`, interval)
		if qtRows != nil {
			defer qtRows.Close()
			for qtRows.Next() {
				var stat StatusCount
				qtRows.Scan(&stat.Status, &stat.Count)
				stats.QueryTypes = append(stats.QueryTypes, stat)
			}
		}

		// Cached count
		s.db.QueryRow(`
			SELECT COALESCE(SUM(logs_cached), 0) FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'dns'
		`, interval).Scan(&stats.CachedCount)

		// Blocked count
		s.db.QueryRow(`
			SELECT COUNT(*) FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'dns'
			  AND (logs_status LIKE '%BLOCK%' OR logs_status LIKE '%FILTER%')
		`, interval).Scan(&stats.BlockedCount)

		// Top blocked domains
		blockedRows, _ := s.db.Query(`
			SELECT logs_domain, COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'dns'
			  AND logs_domain != ''
			  AND (logs_status LIKE '%BLOCK%' OR logs_status LIKE '%FILTER%')
			GROUP BY logs_domain ORDER BY cnt DESC LIMIT 10
		`, interval)
		if blockedRows != nil {
			defer blockedRows.Close()
			for blockedRows.Next() {
				var stat DomainStat
				blockedRows.Scan(&stat.Domain, &stat.Count)
				stats.TopBlocked = append(stats.TopBlocked, stat)
			}
		}
	}

	// ── OUTBOUND ──────────────────────────────────────────────────────

	if logType == "outbound" || logType == "" {
		// Protocol mix
		protoRows, _ := s.db.Query(`
			SELECT logs_protocol, COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'outbound'
			  AND logs_protocol != ''
			GROUP BY logs_protocol ORDER BY cnt DESC
		`, interval)
		if protoRows != nil {
			defer protoRows.Close()
			for protoRows.Next() {
				var stat StatusCount
				protoRows.Scan(&stat.Status, &stat.Count)
				stats.Protocols = append(stats.Protocols, stat)
			}
		}

		// Top destination IPs
		destRows, _ := s.db.Query(`
			SELECT logs_dest_ip, COALESCE(logs_dest_country, ''), COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'outbound'
			  AND logs_dest_ip != ''
			GROUP BY logs_dest_ip ORDER BY cnt DESC LIMIT 10
		`, interval)
		if destRows != nil {
			defer destRows.Close()
			for destRows.Next() {
				var stat ClientStat
				destRows.Scan(&stat.IP, &stat.Country, &stat.Count)
				stats.TopDestIPs = append(stats.TopDestIPs, stat)
			}
		}
	}

	// ── FIREWALL ──────────────────────────────────────────────────────

	if logType == "fw" || logType == "" {
		// Top destination ports being probed
		portRows, _ := s.db.Query(`
			SELECT CAST(logs_dest_port AS TEXT), COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'fw'
			  AND logs_dest_port > 0
			GROUP BY logs_dest_port ORDER BY cnt DESC LIMIT 10
		`, interval)
		if portRows != nil {
			defer portRows.Close()
			for portRows.Next() {
				var stat StatusCount
				portRows.Scan(&stat.Status, &stat.Count)
				stats.TopDestPorts = append(stats.TopDestPorts, stat)
			}
		}

		// Top firewall rules that fired
		ruleRows, _ := s.db.Query(`
			SELECT logs_rule, COUNT(*) as cnt FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'fw'
			  AND logs_rule != ''
			GROUP BY logs_rule ORDER BY cnt DESC LIMIT 10
		`, interval)
		if ruleRows != nil {
			defer ruleRows.Close()
			for ruleRows.Next() {
				var stat StatusCount
				ruleRows.Scan(&stat.Status, &stat.Count)
				stats.TopRules = append(stats.TopRules, stat)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleGetStatus handles GET /api/logs/status
func (s *Service) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	statuses := s.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statuses)
}

// handleSetWatcher handles POST /api/logs/watcher
func (s *Service) handleSetWatcher(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Enable bool   `json:"enable"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !s.EnableWatcher(req.Name, req.Enable) {
		router.JSONError(w, "watcher not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
