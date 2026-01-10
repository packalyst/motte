package firewall

import (
	"net/http"
	"regexp"

	"api/internal/helper"
	"api/internal/router"
)

// jailQueryBase is the common SELECT for jail queries
const jailQueryBase = `
	SELECT j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action,
		COUNT(CASE WHEN f.id IS NOT NULL AND f.enabled = 1 AND (f.expires_at IS NULL OR f.expires_at > datetime('now')) THEN 1 END) as currently_banned,
		COUNT(f.id) as total_banned,
		COALESCE(j.escalate_enabled, 0), COALESCE(j.escalate_threshold, 3), COALESCE(j.escalate_window, 3600)
	FROM jails j
	LEFT JOIN firewall_entries f ON j.name = f.name AND f.entry_type IN ('ip', 'range') AND f.action = 'block'`

const jailGroupBy = `
	GROUP BY j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action,
		j.escalate_enabled, j.escalate_threshold, j.escalate_window`

// handleGetJails returns all jails
func (s *Service) handleGetJails(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(jailQueryBase + jailGroupBy)
	if err != nil {
		router.JSONError(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	jails := []Jail{}
	for rows.Next() {
		var j Jail
		if err := rows.Scan(&j.ID, &j.Name, &j.Enabled, &j.LogFile, &j.FilterRegex, &j.MaxRetry, &j.FindTime, &j.BanTime, &j.Port, &j.Action,
			&j.CurrentlyBanned, &j.TotalBanned, &j.EscalateEnabled, &j.EscalateThreshold, &j.EscalateWindow); err != nil {
			continue
		}
		jails = append(jails, j)
	}
	router.JSON(w, jails)
}

// handleCreateJail creates a new jail
func (s *Service) handleCreateJail(w http.ResponseWriter, r *http.Request) {
	var jail Jail
	if !router.DecodeJSONOrError(w, r, &jail) {
		return
	}

	if jail.FilterRegex != "" {
		if _, err := regexp.Compile(jail.FilterRegex); err != nil {
			router.JSONError(w, "invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Validate log file path to prevent path traversal
	if jail.LogFile != "" {
		if err := helper.ValidateLogFilePath(jail.LogFile); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if jail.EscalateThreshold == 0 {
		jail.EscalateThreshold = 3
	}
	if jail.EscalateWindow == 0 {
		jail.EscalateWindow = 3600
	}

	result, err := s.db.Exec(`INSERT INTO jails (name, enabled, log_file, filter_regex, max_retry, find_time, ban_time, port, action,
		escalate_enabled, escalate_threshold, escalate_window)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jail.Name, jail.Enabled, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.Port, jail.Action,
		jail.EscalateEnabled, jail.EscalateThreshold, jail.EscalateWindow)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jail.ID, _ = result.LastInsertId()

	if jail.Enabled {
		s.startJailMonitor(jail.ID, jail.Name, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, 0)
	}

	router.JSON(w, jail)
}

// handleGetJail returns a single jail
func (s *Service) handleGetJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")
	var jail Jail
	err := s.db.QueryRow(jailQueryBase+" WHERE j.name = ?"+jailGroupBy, name).Scan(
		&jail.ID, &jail.Name, &jail.Enabled, &jail.LogFile, &jail.FilterRegex,
		&jail.MaxRetry, &jail.FindTime, &jail.BanTime, &jail.Port, &jail.Action,
		&jail.CurrentlyBanned, &jail.TotalBanned,
		&jail.EscalateEnabled, &jail.EscalateThreshold, &jail.EscalateWindow)
	if err != nil {
		router.JSONError(w, "jail not found", http.StatusNotFound)
		return
	}
	router.JSON(w, jail)
}

// handleUpdateJail updates a jail
func (s *Service) handleUpdateJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")
	var jail Jail
	if !router.DecodeJSONOrError(w, r, &jail) {
		return
	}

	if jail.FilterRegex != "" {
		if _, err := regexp.Compile(jail.FilterRegex); err != nil {
			router.JSONError(w, "invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Validate log file path to prevent path traversal
	if jail.LogFile != "" {
		if err := helper.ValidateLogFilePath(jail.LogFile); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	var jailID int64
	_ = s.db.QueryRow("SELECT id FROM jails WHERE name = ?", name).Scan(&jailID)

	_, err := s.db.Exec(`UPDATE jails SET enabled = ?, log_file = ?, filter_regex = ?, max_retry = ?,
		find_time = ?, ban_time = ?, port = ?, action = ?,
		escalate_enabled = ?, escalate_threshold = ?, escalate_window = ? WHERE name = ?`,
		jail.Enabled, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.Port, jail.Action,
		jail.EscalateEnabled, jail.EscalateThreshold, jail.EscalateWindow, name)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if jailID > 0 {
		s.restartJailMonitor(jailID)
	}

	jail.ID = jailID
	router.JSON(w, jail)
}

// handleDeleteJail deletes a jail
func (s *Service) handleDeleteJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")

	var jailID int64
	_ = s.db.QueryRow("SELECT id FROM jails WHERE name = ?", name).Scan(&jailID)
	if jailID > 0 {
		s.stopJailMonitor(jailID)
	}

	s.db.Exec("DELETE FROM jails WHERE name = ?", name)
	s.db.Exec("DELETE FROM firewall_entries WHERE source = ? AND entry_type IN ('ip', 'range')", name)
	s.RequestApply()
	w.WriteHeader(http.StatusNoContent)
}
