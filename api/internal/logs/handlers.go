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

// StatsResponse represents aggregated stats
type StatsResponse struct {
	TopDomains   []DomainStat  `json:"top_domains"`
	TopClients   []ClientStat  `json:"top_clients"`
	TopCountries []CountryStat `json:"top_countries"`
	StatusCounts []StatusCount `json:"status_counts"`
	TotalCount   int           `json:"total_count"`
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

// handleGetStats handles GET /api/logs/stats
func (s *Service) handleGetStats(w http.ResponseWriter, r *http.Request) {
	logType := r.URL.Query().Get("type")
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "day"
	}

	var interval string
	switch period {
	case "hour":
		interval = "-1 hour"
	case "week":
		interval = "-7 days"
	default:
		interval = "-1 day"
	}

	typeFilter := ""
	args := []interface{}{interval}
	if logType != "" {
		typeFilter = " AND logs_type = ?"
		args = append(args, logType)
	}

	stats := StatsResponse{}

	// Top domains
	domainRows, _ := s.db.Query(`
		SELECT logs_domain, COUNT(*) as cnt
		FROM logs
		WHERE logs_timestamp > datetime('now', ?)
		  AND logs_domain != ''`+typeFilter+`
		GROUP BY logs_domain
		ORDER BY cnt DESC
		LIMIT 10
	`, args...)
	if domainRows != nil {
		defer domainRows.Close()
		for domainRows.Next() {
			var stat DomainStat
			domainRows.Scan(&stat.Domain, &stat.Count)
			stats.TopDomains = append(stats.TopDomains, stat)
		}
	}

	// Top clients
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

	// Top countries (destination for outbound, source for inbound/dns)
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

	// Status counts (for DNS)
	if logType == "dns" || logType == "" {
		statusRows, _ := s.db.Query(`
			SELECT logs_status, COUNT(*) as cnt
			FROM logs
			WHERE logs_timestamp > datetime('now', ?)
			  AND logs_type = 'dns'
			  AND logs_status != ''
			GROUP BY logs_status
			ORDER BY cnt DESC
		`, interval)
		if statusRows != nil {
			defer statusRows.Close()
			for statusRows.Next() {
				var stat StatusCount
				statusRows.Scan(&stat.Status, &stat.Count)
				stats.StatusCounts = append(stats.StatusCounts, stat)
			}
		}
	}

	// Total count
	s.db.QueryRow(`
		SELECT COUNT(*) FROM logs
		WHERE logs_timestamp > datetime('now', ?)`+typeFilter,
		args...,
	).Scan(&stats.TotalCount)

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
