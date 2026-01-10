package firewall

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/nftables"
	"api/internal/router"
)

// handleGetEntries returns firewall entries with pagination and filters
func (s *Service) handleGetEntries(w http.ResponseWriter, r *http.Request) {
	p := router.ParsePagination(r, helper.DefaultPaginationLimit)
	search := r.URL.Query().Get("search")
	typeFilter := r.URL.Query().Get("type")     // ip, range, country, port
	sourceFilter := r.URL.Query().Get("source") // manual, fail2ban, blocklist, etc.
	actionFilter := r.URL.Query().Get("action") // block, allow

	where := "(expires_at IS NULL OR expires_at > datetime('now'))"
	args := []interface{}{}

	if typeFilter != "" {
		where += " AND entry_type = ?"
		args = append(args, typeFilter)
	}

	if sourceFilter != "" {
		where += " AND source = ?"
		args = append(args, sourceFilter)
	}

	if actionFilter != "" {
		where += " AND action = ?"
		args = append(args, actionFilter)
	}

	if search != "" {
		where += " AND (value LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\' OR reason LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\')"
		searchPattern := "%" + database.EscapeLikePattern(search) + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM firewall_entries WHERE " + where
	_ = s.db.QueryRow(countQuery, args...).Scan(&total)

	// Get filter options (types are known constants, only sources need DB query)
	types := []string{"ip", "range", "country", "port"}
	sources := s.getDistinctValues("firewall_entries", "source")

	query := fmt.Sprintf(`SELECT id, entry_type, value, action, direction, protocol, source,
		COALESCE(reason, ''), COALESCE(name, ''), essential, expires_at, enabled, hit_count, created_at
		FROM firewall_entries WHERE %s ORDER BY created_at DESC LIMIT ? OFFSET ?`, where)
	args = append(args, p.Limit, p.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		router.JSONError(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	entries := []nftables.FirewallEntry{}
	for rows.Next() {
		var e nftables.FirewallEntry
		var expiresAt sql.NullTime
		if err := rows.Scan(&e.ID, &e.EntryType, &e.Value, &e.Action, &e.Direction, &e.Protocol,
			&e.Source, &e.Reason, &e.Name, &e.Essential, &expiresAt, &e.Enabled,
			&e.HitCount, &e.CreatedAt); err != nil {
			continue
		}
		e.ExpiresAt = database.TimePointerFromNull(expiresAt)
		entries = append(entries, e)
	}

	router.JSON(w, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"limit":   p.Limit,
		"offset":  p.Offset,
		"types":   types,
		"sources": sources,
	})
}

// handleCreateEntry creates a new firewall entry
func (s *Service) handleCreateEntry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type      string `json:"type"`      // ip, range, country, port
		Value     string `json:"value"`     // IP, CIDR, country code, port number
		Action    string `json:"action"`    // block, allow (default: block for ip/range/country, allow for port)
		Direction string `json:"direction"` // inbound, outbound, both
		Protocol  string `json:"protocol"`  // tcp, udp, both
		Reason    string `json:"reason"`
		Name      string `json:"name"`    // country name or port service name
		BanTime   int    `json:"banTime"` // seconds, 0 = permanent
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate type
	validTypes := map[string]bool{
		nftables.EntryTypeIP:      true,
		nftables.EntryTypeRange:   true,
		nftables.EntryTypeCountry: true,
		nftables.EntryTypePort:    true,
	}
	if !validTypes[req.Type] {
		router.JSONError(w, "invalid type: must be ip, range, country, or port", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.Action == "" {
		if req.Type == nftables.EntryTypePort {
			req.Action = nftables.ActionAllow
		} else {
			req.Action = nftables.ActionBlock
		}
	}
	if req.Direction == "" {
		req.Direction = nftables.DirectionInbound
	}
	if req.Protocol == "" {
		req.Protocol = nftables.ProtocolBoth
	}

	// Validate and normalize value based on type
	var normalizedValue string
	switch req.Type {
	case nftables.EntryTypeIP:
		normalized, isRange, err := validateIPOrCIDR(req.Value)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if isRange {
			req.Type = nftables.EntryTypeRange // Auto-upgrade to range if CIDR
		}
		normalizedValue = normalized

		// Self-protection for IPs
		if err := s.validateIPNotProtected(normalizedValue, r); err != nil {
			router.JSONError(w, err.Error(), http.StatusForbidden)
			return
		}

	case nftables.EntryTypeRange:
		normalized, _, err := validateIPOrCIDR(req.Value)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizedValue = normalized

	case nftables.EntryTypeCountry:
		code := strings.ToUpper(strings.TrimSpace(req.Value))
		if len(code) != 2 {
			router.JSONError(w, "country code must be 2 letters (ISO 3166-1 alpha-2)", http.StatusBadRequest)
			return
		}
		normalizedValue = code

	case nftables.EntryTypePort:
		port, err := strconv.Atoi(req.Value)
		if err != nil || port < 1 || port > 65535 {
			router.JSONError(w, "invalid port number (must be 1-65535)", http.StatusBadRequest)
			return
		}
		normalizedValue = req.Value
	}

	var expiresAt interface{}
	if req.BanTime > 0 {
		expiresAt = time.Now().Add(time.Duration(req.BanTime) * time.Second)
	}

	result, err := s.db.Exec(`INSERT INTO firewall_entries
		(entry_type, value, action, direction, protocol, source, reason, name, expires_at, enabled)
		VALUES (?, ?, ?, ?, ?, 'manual', ?, ?, ?, 1)
		ON CONFLICT(entry_type, value, protocol) DO UPDATE SET
		action = excluded.action, direction = excluded.direction, reason = excluded.reason,
		name = excluded.name, expires_at = excluded.expires_at, enabled = 1`,
		req.Type, normalizedValue, req.Action, req.Direction, req.Protocol, req.Reason, req.Name, expiresAt)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()

	// For country entries, fetch zones async
	if req.Type == nftables.EntryTypeCountry {
		router.JSON(w, map[string]interface{}{
			"status": "queued",
			"id":     id,
			"type":   req.Type,
			"value":  normalizedValue,
			"action": req.Action,
		})
		s.FetchCountryZonesAsync([]string{normalizedValue})
		return
	}

	s.RequestApply()
	router.JSON(w, map[string]interface{}{
		"status": "created",
		"id":     id,
		"type":   req.Type,
		"value":  normalizedValue,
		"action": req.Action,
	})
}

// handleDeleteEntry deletes a firewall entry by ID
func (s *Service) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/fw/entries/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}

	// Check if essential
	var essential bool
	err = s.db.QueryRow("SELECT essential FROM firewall_entries WHERE id = ?", id).Scan(&essential)
	if err == sql.ErrNoRows {
		router.JSONError(w, "entry not found", http.StatusNotFound)
		return
	}
	if essential {
		router.JSONError(w, "cannot delete essential entry", http.StatusForbidden)
		return
	}

	_, err = s.db.Exec("DELETE FROM firewall_entries WHERE id = ? AND essential = 0", id)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.RequestApply()
	w.WriteHeader(http.StatusNoContent)
}

// handleBulkEntries handles bulk operations on entries
func (s *Service) handleBulkEntries(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string  `json:"action"` // create, delete, enable, disable
		IDs     []int64 `json:"ids"`
		Entries []struct {
			Type      string `json:"type"`
			Value     string `json:"value"`
			Action    string `json:"action"`
			Direction string `json:"direction"`
			Name      string `json:"name"`
		} `json:"entries"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Handle bulk create
	if req.Action == "create" {
		if len(req.Entries) == 0 {
			router.JSONError(w, "no entries provided", http.StatusBadRequest)
			return
		}

		created := 0
		var countryEntries []string

		for _, e := range req.Entries {
			action := e.Action
			if action == "" {
				action = nftables.ActionBlock
			}
			direction := e.Direction
			if direction == "" {
				direction = nftables.DirectionInbound
			}

			// Insert entry immediately (zones will be fetched async for countries)
			_, err := s.db.Exec(`INSERT OR IGNORE INTO firewall_entries
				(entry_type, value, action, direction, protocol, source, name, enabled)
				VALUES (?, ?, ?, ?, 'both', 'manual', ?, 1)`,
				e.Type, e.Value, action, direction, e.Name)
			if err == nil {
				created++
				// Track country entries for async zone fetching
				if e.Type == nftables.EntryTypeCountry {
					countryEntries = append(countryEntries, e.Value)
				}
			}
		}

		// Return immediately, fetch zones and apply in background
		router.JSON(w, map[string]interface{}{
			"status":   "queued",
			"created":  created,
			"fetching": len(countryEntries),
		})

		// Async: fetch country zones and apply rules
		s.FetchCountryZonesAsync(countryEntries)
		return
	}

	// Handle delete/enable/disable with IDs
	if len(req.IDs) == 0 {
		router.JSONError(w, "no ids provided", http.StatusBadRequest)
		return
	}

	// Build placeholders
	placeholders := make([]string, len(req.IDs))
	args := make([]interface{}, len(req.IDs))
	for i, id := range req.IDs {
		placeholders[i] = "?"
		args[i] = id
	}
	inClause := strings.Join(placeholders, ",")

	var query string
	switch req.Action {
	case "delete":
		query = fmt.Sprintf("DELETE FROM firewall_entries WHERE id IN (%s) AND essential = 0", inClause)
	case "enable":
		query = fmt.Sprintf("UPDATE firewall_entries SET enabled = 1 WHERE id IN (%s)", inClause)
	case "disable":
		query = fmt.Sprintf("UPDATE firewall_entries SET enabled = 0 WHERE id IN (%s) AND essential = 0", inClause)
	case "set_inbound":
		query = fmt.Sprintf("UPDATE firewall_entries SET direction = 'inbound' WHERE id IN (%s)", inClause)
	case "set_outbound":
		query = fmt.Sprintf("UPDATE firewall_entries SET direction = 'outbound' WHERE id IN (%s)", inClause)
	case "set_both":
		query = fmt.Sprintf("UPDATE firewall_entries SET direction = 'both' WHERE id IN (%s)", inClause)
	default:
		router.JSONError(w, "invalid action: must be create, delete, enable, disable, set_inbound, set_outbound, or set_both", http.StatusBadRequest)
		return
	}

	result, err := s.db.Exec(query, args...)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		s.RequestApply()
	}

	router.JSON(w, map[string]interface{}{
		"status":   req.Action + "d",
		"affected": affected,
	})
}

// handleImportEntries imports entries from a blocklist source
func (s *Service) handleImportEntries(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source string `json:"source"` // blocklist source ID
		URL    string `json:"url"`    // custom URL
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	var entries []string
	var sourceName string

	if req.Source != "" {
		src, exists := blocklistSources[req.Source]
		if !exists {
			router.JSONError(w, "unknown blocklist source", http.StatusBadRequest)
			return
		}
		sourceName = req.Source

		if src.Type == "static" {
			entries = src.Ranges
		} else {
			var err error
			entries, err = s.fetchBlocklist(src.URL, src.MinScore)
			if err != nil {
				router.JSONError(w, "failed to fetch blocklist: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	} else if req.URL != "" {
		if err := helper.ValidateBlocklistURL(req.URL); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		sourceName = "custom"
		var err error
		entries, err = s.fetchBlocklist(req.URL, 0)
		if err != nil {
			router.JSONError(w, "failed to fetch blocklist: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		router.JSONError(w, "source or url required", http.StatusBadRequest)
		return
	}

	added := 0
	skipped := 0
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || isPrivateRange(entry) {
			skipped++
			continue
		}

		normalizedIP, isRange, err := validateIPOrCIDR(entry)
		if err != nil {
			skipped++
			continue
		}

		entryType := nftables.EntryTypeIP
		if isRange {
			entryType = nftables.EntryTypeRange
		}

		result, err := s.db.Exec(`INSERT OR IGNORE INTO firewall_entries
			(entry_type, value, action, direction, protocol, source, reason, enabled)
			VALUES (?, ?, 'block', 'inbound', 'both', ?, ?, 1)`,
			entryType, normalizedIP, sourceName, fmt.Sprintf("Imported from %s", sourceName))
		if err != nil {
			skipped++
			continue
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected > 0 {
			added++
		} else {
			skipped++
		}
	}

	if added > 0 {
		s.RequestApply()
	}

	router.JSON(w, map[string]interface{}{
		"status":  "imported",
		"source":  sourceName,
		"added":   added,
		"skipped": skipped,
		"total":   len(entries),
	})
}

// handleDeleteBySource deletes all entries from a source
func (s *Service) handleDeleteBySource(w http.ResponseWriter, r *http.Request) {
	source := router.ExtractPathParam(r, "/api/fw/entries/source/")
	if source == "" {
		router.JSONError(w, "source required", http.StatusBadRequest)
		return
	}

	result, err := s.db.Exec("DELETE FROM firewall_entries WHERE source = ? AND essential = 0", source)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		s.RequestApply()
	}

	router.JSON(w, map[string]interface{}{
		"status":  "deleted",
		"source":  source,
		"deleted": deleted,
	})
}

// handleDeleteAll deletes all non-essential entries
func (s *Service) handleDeleteAll(w http.ResponseWriter, r *http.Request) {
	result, err := s.db.Exec("DELETE FROM firewall_entries WHERE essential = 0")
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		s.RequestApply()
	}

	router.JSON(w, map[string]interface{}{
		"status":  "deleted",
		"deleted": deleted,
	})
}

// handleToggleEntry enables/disables an entry or changes direction
func (s *Service) handleToggleEntry(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/fw/entries/")
	// Remove /toggle suffix if present
	idStr = strings.TrimSuffix(idStr, "/toggle")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		router.JSONError(w, "invalid id", http.StatusBadRequest)
		return
	}

	var req struct {
		Enabled   *bool  `json:"enabled,omitempty"`
		Direction string `json:"direction,omitempty"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Check if entry exists and get current values
	var essential bool
	var currentEnabled bool
	err = s.db.QueryRow("SELECT essential, enabled FROM firewall_entries WHERE id = ?", id).Scan(&essential, &currentEnabled)
	if err == sql.ErrNoRows {
		router.JSONError(w, "entry not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{"status": "updated"}

	// Handle enabled toggle
	if req.Enabled != nil {
		if essential && !*req.Enabled {
			router.JSONError(w, "cannot disable essential entry", http.StatusForbidden)
			return
		}
		_, err = s.db.Exec("UPDATE firewall_entries SET enabled = ? WHERE id = ?", *req.Enabled, id)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response["enabled"] = *req.Enabled
	}

	// Handle direction change
	if req.Direction != "" {
		validDirections := map[string]bool{
			nftables.DirectionInbound:  true,
			nftables.DirectionOutbound: true,
			nftables.DirectionBoth:     true,
		}
		if !validDirections[req.Direction] {
			router.JSONError(w, "invalid direction", http.StatusBadRequest)
			return
		}
		_, err = s.db.Exec("UPDATE firewall_entries SET direction = ? WHERE id = ?", req.Direction, id)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response["direction"] = req.Direction
	}

	s.RequestApply()
	router.JSON(w, response)
}

// validateIPNotProtected checks if an IP is protected (server IP, requester IP, private)
func (s *Service) validateIPNotProtected(ip string, r *http.Request) error {
	// Don't block private/loopback addresses
	if isPrivateRange(ip) {
		return fmt.Errorf("cannot block private/loopback addresses")
	}

	// Don't block requester's IP
	clientIP := helper.GetClientIP(r)
	if ip == clientIP {
		return fmt.Errorf("cannot block your own IP address")
	}

	// Don't block server's IP
	if s.config.ServerIP != "" && ip == s.config.ServerIP {
		return fmt.Errorf("cannot block the server's IP address")
	}

	return nil
}

// handleGetBlocklists returns available blocklist sources
func (s *Service) handleGetBlocklists(w http.ResponseWriter, r *http.Request) {
	sources := []BlocklistSource{}
	for _, src := range blocklistSources {
		sources = append(sources, src)
	}
	router.JSON(w, sources)
}
