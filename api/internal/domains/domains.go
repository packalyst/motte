package domains

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"api/internal/adguard"
	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/traefik"
)

// ensureVPNMiddleware adds sentinel_vpn@file if no VPN middleware exists
func ensureVPNMiddleware(middlewares []string) []string {
	for _, mw := range middlewares {
		if mw == traefik.MiddlewareSentinelVPNFile || mw == traefik.MiddlewareSentinelVPNSilentFile {
			return middlewares // already has VPN middleware
		}
	}
	return append(middlewares, traefik.MiddlewareSentinelVPNFile)
}

// validateSentinelConfig validates sentinel config fields
func validateSentinelConfig(sc *traefik.SentinelConfig) error {
	if sc == nil {
		return nil
	}

	// Validate IP ranges
	if err := helper.ValidateIPList(sc.IPFilter.SourceRange); err != nil {
		return fmt.Errorf("invalid IP filter: %w", err)
	}

	// Validate error mode
	switch sc.ErrorMode {
	case "", "403", "404", "503", "silent":
		// valid
	default:
		return fmt.Errorf("invalid errorMode: %s", sc.ErrorMode)
	}

	// Validate time range format (HH:MM-HH:MM)
	timeRangeRegex := regexp.MustCompile(`^([01]?[0-9]|2[0-3]):[0-5][0-9]-([01]?[0-9]|2[0-3]):[0-5][0-9]$`)
	if sc.TimeAccess != nil {
		if sc.TimeAccess.AllowRange != "" && !timeRangeRegex.MatchString(sc.TimeAccess.AllowRange) {
			return fmt.Errorf("invalid allowRange format: %s (expected HH:MM-HH:MM)", sc.TimeAccess.AllowRange)
		}
		if sc.TimeAccess.DenyRange != "" && !timeRangeRegex.MatchString(sc.TimeAccess.DenyRange) {
			return fmt.Errorf("invalid denyRange format: %s (expected HH:MM-HH:MM)", sc.TimeAccess.DenyRange)
		}
		// Validate days are valid lowercase 3-letter names
		validDays := map[string]bool{"mon": true, "tue": true, "wed": true, "thu": true, "fri": true, "sat": true, "sun": true}
		for _, day := range sc.TimeAccess.Days {
			if !validDays[strings.ToLower(day)] {
				return fmt.Errorf("invalid day: %s (expected mon, tue, wed, thu, fri, sat, sun)", day)
			}
		}
	}

	// Validate user agent regex patterns (try to compile them)
	if sc.UserAgents != nil {
		for i, pattern := range sc.UserAgents.Block {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("invalid block pattern at index %d: %v", i, err)
			}
		}
		for i, pattern := range sc.UserAgents.Allow {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("invalid allow pattern at index %d: %v", i, err)
			}
		}
	}

	// Validate header rules
	for i, h := range sc.Headers {
		if h.Name == "" {
			return fmt.Errorf("header rule at index %d has empty name", i)
		}
		if h.Regex != "" {
			if _, err := regexp.Compile(h.Regex); err != nil {
				return fmt.Errorf("invalid header regex at index %d: %v", i, err)
			}
		}
	}

	// Limit array sizes to prevent abuse
	if len(sc.IPFilter.SourceRange) > 100 {
		return fmt.Errorf("too many IP ranges (max 100)")
	}
	if len(sc.Headers) > 20 {
		return fmt.Errorf("too many header rules (max 20)")
	}
	if sc.UserAgents != nil && (len(sc.UserAgents.Block)+len(sc.UserAgents.Allow)) > 50 {
		return fmt.Errorf("too many user agent patterns (max 50)")
	}

	return nil
}

// parseRouteFields parses common route fields from DB scan results (DRY helper)
func parseRouteFields(middlewaresJSON string, accessMode sql.NullString, frontendSSL sql.NullBool, sentinelConfigJSON string) ([]string, string, bool, *traefik.SentinelConfig) {
	var middlewares []string
	if err := json.Unmarshal([]byte(middlewaresJSON), &middlewares); err != nil {
		middlewares = []string{}
	}
	return middlewares,
		database.StringFromNullNotEmpty(accessMode, "vpn"),
		database.BoolFromNull(frontendSSL, false),
		parseSentinelConfig(sentinelConfigJSON)
}

// parseSentinelConfig parses JSON string to SentinelConfig (DRY helper)
func parseSentinelConfig(jsonStr string) *traefik.SentinelConfig {
	if jsonStr == "" {
		return nil
	}
	var sc traefik.SentinelConfig
	if err := json.Unmarshal([]byte(jsonStr), &sc); err != nil {
		log.Printf("Warning: failed to parse sentinel config: %v", err)
		return nil
	}
	return &sc
}

// Service handles domain routes
type Service struct {
	traefikConfigDir string
	vpnIP            string // VPN IP for DNS rewrites (e.g., 10.8.0.1)
	publicIP         string // Public IP for reference
}

// DomainRoute represents a domain to port mapping
type DomainRoute struct {
	ID             int                    `json:"id"`
	Domain         string                 `json:"domain"`
	TargetIP       string                 `json:"targetIp"`
	TargetPort     int                    `json:"targetPort"`
	VPNClientID    *int                   `json:"vpnClientId,omitempty"`
	Enabled        bool                   `json:"enabled"`
	HTTPSBackend   bool                   `json:"httpsBackend"`
	Middlewares    []string               `json:"middlewares"`
	Description    string                 `json:"description"`
	AccessMode     string                 `json:"accessMode"`      // "vpn" or "public"
	FrontendSSL    bool                   `json:"frontendSsl"`     // use websecure entrypoint
	SentinelConfig *traefik.SentinelConfig `json:"sentinelConfig,omitempty"`
	CreatedAt      time.Time              `json:"createdAt"`
	UpdatedAt      time.Time              `json:"updatedAt"`
	VPNClientName  string                 `json:"vpnClientName,omitempty"`
}


// New creates a new domains service
func New() *Service {
	svc := &Service{
		traefikConfigDir: helper.GetEnvOptional("TRAEFIK_CONFIG", "/traefik/dynamic"),
		vpnIP:            helper.GetEnvOptional("WG_SERVER_IP", "10.8.0.1"), // VPN IP for VPN-only domains
		publicIP:         helper.GetEnvOptional("SERVER_IP", "127.0.0.1"),   // Public IP (for reference)
	}
	log.Printf("Domains service initialized, Traefik config: %s, VPN IP: %s", svc.traefikConfigDir, svc.vpnIP)
	return svc
}

// ApplyRoutes generates Traefik config and syncs AdGuard DNS (exported for use by other packages)
func ApplyRoutes() error {
	traefikConfigDir := helper.GetEnvOptional("TRAEFIK_CONFIG", "/traefik/dynamic")
	vpnIP := helper.GetEnvOptional("WG_SERVER_IP", "10.8.0.1") // VPN IP for DNS rewrites

	db, err := database.GetDB()
	if err != nil {
		return err
	}

	// Get all enabled routes with new columns
	rows, err := db.Query(`
		SELECT domain, target_ip, target_port, https_backend, middlewares, access_mode, frontend_ssl, COALESCE(sentinel_config, '')
		FROM domain_routes
		WHERE enabled = 1
		ORDER BY domain
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	routes := []traefik.DomainRouteConfig{}
	vpnDomains := []adguard.DomainRoute{} // Only VPN mode domains for AdGuard

	for rows.Next() {
		var rc traefik.DomainRouteConfig
		var middlewaresJSON string
		var accessMode sql.NullString
		var frontendSSL sql.NullBool
		var sentinelConfigJSON string

		if err := rows.Scan(&rc.Domain, &rc.TargetIP, &rc.TargetPort, &rc.HTTPSBackend, &middlewaresJSON, &accessMode, &frontendSSL, &sentinelConfigJSON); err != nil {
			continue
		}
		rc.Middlewares, rc.AccessMode, rc.FrontendSSL, rc.SentinelConfig = parseRouteFields(middlewaresJSON, accessMode, frontendSSL, sentinelConfigJSON)

		// Add VPN domains to AdGuard sync list
		if rc.AccessMode == "vpn" {
			vpnDomains = append(vpnDomains, adguard.DomainRoute{Domain: rc.Domain})
		}

		routes = append(routes, rc)
	}

	// Generate Traefik config
	if err := traefik.GenerateDomainRoutes(traefikConfigDir, routes); err != nil {
		return fmt.Errorf("failed to generate Traefik config: %v", err)
	}

	// Sync AdGuard DNS only for VPN mode domains (rewrite to VPN IP, not public IP!)
	dnsErrors := adguard.SyncDomainRewrites(vpnDomains, vpnIP)
	if len(dnsErrors) > 0 {
		log.Printf("DNS sync warnings: %v", dnsErrors)
	}

	log.Printf("Applied %d domain routes (%d VPN mode with DNS)", len(routes), len(vpnDomains))
	return nil
}

// applyRoutes calls the exported ApplyRoutes function (internal wrapper for service methods)
func (s *Service) applyRoutes() error {
	return ApplyRoutes()
}

// DeleteClientRoutes removes all domain routes for a VPN client and applies changes
func DeleteClientRoutes(clientID int) (int, error) {
	db, err := database.GetDB()
	if err != nil {
		return 0, err
	}

	result, err := db.Exec(`DELETE FROM domain_routes WHERE vpn_client_id = ?`, clientID)
	if err != nil {
		return 0, err
	}

	rows, _ := result.RowsAffected()
	if rows > 0 {
		log.Printf("Deleted %d domain routes for VPN client %d", rows, clientID)
		if err := ApplyRoutes(); err != nil {
			log.Printf("Warning: failed to apply routes after client deletion: %v", err)
		}
	}

	return int(rows), nil
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"List":            s.handleList,
		"Get":             s.handleGet,
		"Create":          s.handleCreate,
		"Update":          s.handleUpdate,
		"Delete":          s.handleDelete,
		"Toggle":          s.handleToggle,
		"GetCertificates": s.handleGetCertificates,
		"GetSystemDomain": s.handleGetSystemDomain,
	}
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, err := db.Query(`
		SELECT d.id, d.domain, d.target_ip, d.target_port, d.vpn_client_id,
		       d.enabled, d.https_backend, d.middlewares, d.description,
		       d.access_mode, d.frontend_ssl, COALESCE(d.sentinel_config, ''),
		       d.created_at, d.updated_at, COALESCE(v.name, '') as vpn_client_name
		FROM domain_routes d
		LEFT JOIN vpn_clients v ON d.vpn_client_id = v.id
		ORDER BY d.domain
	`)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	routes := []DomainRoute{}
	for rows.Next() {
		var route DomainRoute
		var vpnClientID sql.NullInt64
		var middlewaresJSON string
		var accessMode sql.NullString
		var frontendSSL sql.NullBool
		var sentinelConfigJSON string
		if err := rows.Scan(
			&route.ID, &route.Domain, &route.TargetIP, &route.TargetPort,
			&vpnClientID, &route.Enabled, &route.HTTPSBackend, &middlewaresJSON,
			&route.Description, &accessMode, &frontendSSL, &sentinelConfigJSON,
			&route.CreatedAt, &route.UpdatedAt, &route.VPNClientName,
		); err != nil {
			continue
		}
		if vpnClientID.Valid {
			id := int(vpnClientID.Int64)
			route.VPNClientID = &id
		}
		route.Middlewares, route.AccessMode, route.FrontendSSL, route.SentinelConfig = parseRouteFields(middlewaresJSON, accessMode, frontendSSL, sentinelConfigJSON)
		routes = append(routes, route)
	}

	router.JSON(w, map[string]interface{}{
		"routes": routes,
		"count":  len(routes),
	})
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/domains/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var route DomainRoute
	var vpnClientID sql.NullInt64
	var middlewaresJSON string
	var accessMode sql.NullString
	var frontendSSL sql.NullBool
	var sentinelConfigJSON string
	err = db.QueryRow(`
		SELECT d.id, d.domain, d.target_ip, d.target_port, d.vpn_client_id,
		       d.enabled, d.https_backend, d.middlewares, d.description,
		       d.access_mode, d.frontend_ssl, COALESCE(d.sentinel_config, ''),
		       d.created_at, d.updated_at, COALESCE(v.name, '') as vpn_client_name
		FROM domain_routes d
		LEFT JOIN vpn_clients v ON d.vpn_client_id = v.id
		WHERE d.id = ?
	`, id).Scan(
		&route.ID, &route.Domain, &route.TargetIP, &route.TargetPort,
		&vpnClientID, &route.Enabled, &route.HTTPSBackend, &middlewaresJSON,
		&route.Description, &accessMode, &frontendSSL, &sentinelConfigJSON,
		&route.CreatedAt, &route.UpdatedAt, &route.VPNClientName,
	)
	if err == sql.ErrNoRows {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if vpnClientID.Valid {
		id := int(vpnClientID.Int64)
		route.VPNClientID = &id
	}
	route.Middlewares, route.AccessMode, route.FrontendSSL, route.SentinelConfig = parseRouteFields(middlewaresJSON, accessMode, frontendSSL, sentinelConfigJSON)

	router.JSON(w, route)
}

// CreateRequest for creating a domain route
type CreateRequest struct {
	Domain         string                  `json:"domain"`
	TargetIP       string                  `json:"targetIp"`
	TargetPort     int                     `json:"targetPort"`
	VPNClientID    *int                    `json:"vpnClientId,omitempty"`
	HTTPSBackend   bool                    `json:"httpsBackend"`
	Middlewares    []string                `json:"middlewares"`
	Description    string                  `json:"description"`
	AccessMode     string                  `json:"accessMode"`  // "vpn" or "public", defaults to "vpn"
	FrontendSSL    bool                    `json:"frontendSsl"` // use websecure entrypoint
	SentinelConfig *traefik.SentinelConfig `json:"sentinelConfig,omitempty"`
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate domain
	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	if err := helper.ValidateDomain(req.Domain); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate IP
	req.TargetIP = strings.TrimSpace(req.TargetIP)
	if err := helper.ValidateIP(req.TargetIP); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate port
	if err := helper.ValidatePort(req.TargetPort); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate access_mode (default to "vpn" if empty)
	if req.AccessMode == "" {
		req.AccessMode = "vpn"
	}
	if req.AccessMode != "vpn" && req.AccessMode != "public" {
		router.JSONError(w, "accessMode must be 'vpn' or 'public'", http.StatusBadRequest)
		return
	}

	// For VPN mode, ensure a VPN middleware is present
	if req.AccessMode == "vpn" {
		req.Middlewares = ensureVPNMiddleware(req.Middlewares)
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Validate sentinel config if provided
	if req.SentinelConfig != nil {
		if err := validateSentinelConfig(req.SentinelConfig); err != nil {
			router.JSONError(w, "invalid sentinel config: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Serialize middlewares to JSON
	middlewaresJSON, _ := json.Marshal(req.Middlewares)
	if req.Middlewares == nil {
		middlewaresJSON = []byte("[]")
	}

	// Serialize sentinel config to JSON
	var sentinelConfigJSON string
	if req.SentinelConfig != nil {
		b, _ := json.Marshal(req.SentinelConfig)
		sentinelConfigJSON = string(b)
	}

	result, err := db.Exec(`
		INSERT INTO domain_routes (domain, target_ip, target_port, vpn_client_id, https_backend, middlewares, description, access_mode, frontend_ssl, sentinel_config)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Domain, req.TargetIP, req.TargetPort, req.VPNClientID, req.HTTPSBackend, string(middlewaresJSON), req.Description, req.AccessMode, req.FrontendSSL, sentinelConfigJSON)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			router.JSONError(w, "domain already exists", http.StatusConflict)
			return
		}
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()

	// Auto-apply after create
	if err := s.applyRoutes(); err != nil {
		log.Printf("Warning: failed to apply routes after create: %v", err)
	}

	router.JSON(w, map[string]interface{}{
		"id":      id,
		"message": "route created and applied",
	})
}

// UpdateRequest for updating a domain route
type UpdateRequest struct {
	Domain         *string                 `json:"domain,omitempty"`
	TargetIP       *string                 `json:"targetIp,omitempty"`
	TargetPort     *int                    `json:"targetPort,omitempty"`
	VPNClientID    *int                    `json:"vpnClientId,omitempty"`
	HTTPSBackend   *bool                   `json:"httpsBackend,omitempty"`
	Middlewares    *[]string               `json:"middlewares,omitempty"`
	Description    *string                 `json:"description,omitempty"`
	AccessMode     *string                 `json:"accessMode,omitempty"`
	FrontendSSL    *bool                   `json:"frontendSsl,omitempty"`
	SentinelConfig *traefik.SentinelConfig `json:"sentinelConfig"` // No omitempty - null means clear
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/domains/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	// Read raw body to detect if sentinelConfig key was present
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		router.JSONError(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req UpdateRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		router.JSONError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check if sentinelConfig key was explicitly present in JSON
	var rawMap map[string]json.RawMessage
	json.Unmarshal(bodyBytes, &rawMap)
	sentinelConfigPresent := false
	sentinelConfigNull := false
	if raw, exists := rawMap["sentinelConfig"]; exists {
		sentinelConfigPresent = true
		sentinelConfigNull = string(raw) == "null"
	}

	// Validate fields if provided
	if req.Domain != nil {
		domain := strings.TrimSpace(strings.ToLower(*req.Domain))
		if err := helper.ValidateDomain(domain); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		*req.Domain = domain
	}
	if req.TargetIP != nil {
		ip := strings.TrimSpace(*req.TargetIP)
		if err := helper.ValidateIP(ip); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		*req.TargetIP = ip
	}
	if req.TargetPort != nil {
		if err := helper.ValidatePort(*req.TargetPort); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get current domain and access_mode for AdGuard cleanup
	var oldDomain string
	var oldAccessMode sql.NullString
	err = db.QueryRow("SELECT domain, access_mode FROM domain_routes WHERE id = ?", id).Scan(&oldDomain, &oldAccessMode)
	if err != nil {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}
	oldMode := database.StringFromNullNotEmpty(oldAccessMode, "vpn")

	// Determine if we need to delete old AdGuard entry
	needsAdGuardCleanup := false
	if oldMode == "vpn" {
		// Delete if: domain is changing OR access mode changing from vpn to public
		if req.Domain != nil && *req.Domain != oldDomain {
			needsAdGuardCleanup = true
		}
		if req.AccessMode != nil && *req.AccessMode == "public" {
			needsAdGuardCleanup = true
		}
	}

	// Clean up old AdGuard entry before making changes
	if needsAdGuardCleanup {
		if err := adguard.DeleteDomainRewrite(oldDomain, s.vpnIP); err != nil {
			log.Printf("Warning: failed to delete old AdGuard rewrite for %s: %v", oldDomain, err)
		}
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	if req.Domain != nil {
		updates = append(updates, "domain = ?")
		args = append(args, *req.Domain)
	}
	if req.TargetIP != nil {
		updates = append(updates, "target_ip = ?")
		args = append(args, *req.TargetIP)
	}
	if req.TargetPort != nil {
		updates = append(updates, "target_port = ?")
		args = append(args, *req.TargetPort)
	}
	if req.VPNClientID != nil {
		updates = append(updates, "vpn_client_id = ?")
		args = append(args, *req.VPNClientID)
	}
	if req.HTTPSBackend != nil {
		updates = append(updates, "https_backend = ?")
		args = append(args, *req.HTTPSBackend)
	}
	if req.AccessMode != nil {
		if *req.AccessMode != "vpn" && *req.AccessMode != "public" {
			router.JSONError(w, "accessMode must be 'vpn' or 'public'", http.StatusBadRequest)
			return
		}
		updates = append(updates, "access_mode = ?")
		args = append(args, *req.AccessMode)
	}

	// For VPN mode, ensure a VPN middleware is present
	// Determine effective access mode (new value or existing oldMode)
	effectiveAccessMode := oldMode
	if req.AccessMode != nil {
		effectiveAccessMode = *req.AccessMode
	}

	if effectiveAccessMode == "vpn" {
		if req.Middlewares != nil {
			// Middlewares provided - ensure VPN middleware
			*req.Middlewares = ensureVPNMiddleware(*req.Middlewares)
		} else {
			// Middlewares not provided - fetch current and ensure VPN middleware
			var middlewaresJSON sql.NullString
			if err := db.QueryRow("SELECT middlewares FROM domain_routes WHERE id = ?", id).Scan(&middlewaresJSON); err != nil {
				log.Printf("Warning: could not fetch middlewares for route %d: %v", id, err)
			}
			var currentMiddlewares []string
			if middlewaresJSON.Valid && middlewaresJSON.String != "" {
				json.Unmarshal([]byte(middlewaresJSON.String), &currentMiddlewares)
			}
			currentMiddlewares = ensureVPNMiddleware(currentMiddlewares)
			req.Middlewares = &currentMiddlewares
		}
	}

	if req.Middlewares != nil {
		middlewaresJSON, _ := json.Marshal(*req.Middlewares)
		updates = append(updates, "middlewares = ?")
		args = append(args, string(middlewaresJSON))
	}
	if req.Description != nil {
		updates = append(updates, "description = ?")
		args = append(args, *req.Description)
	}
	if req.FrontendSSL != nil {
		updates = append(updates, "frontend_ssl = ?")
		args = append(args, *req.FrontendSSL)
	}
	// SentinelConfig: handle null (clear) vs object (update) vs omitted (no change)
	if sentinelConfigPresent {
		if sentinelConfigNull {
			// Explicitly set to null - clear the config
			updates = append(updates, "sentinel_config = ?")
			args = append(args, "")
		} else if req.SentinelConfig != nil {
			// Validate the config
			if err := validateSentinelConfig(req.SentinelConfig); err != nil {
				router.JSONError(w, "invalid sentinel config: "+err.Error(), http.StatusBadRequest)
				return
			}
			// Serialize to JSON
			b, _ := json.Marshal(req.SentinelConfig)
			updates = append(updates, "sentinel_config = ?")
			args = append(args, string(b))
		}
	}

	if len(updates) == 0 {
		router.JSONError(w, "no fields to update", http.StatusBadRequest)
		return
	}

	updates = append(updates, "updated_at = CURRENT_TIMESTAMP")
	args = append(args, id)

	query := fmt.Sprintf("UPDATE domain_routes SET %s WHERE id = ?", strings.Join(updates, ", "))
	result, err := db.Exec(query, args...)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			router.JSONError(w, "domain already exists", http.StatusConflict)
			return
		}
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}

	// Auto-apply after update
	if err := s.applyRoutes(); err != nil {
		log.Printf("Warning: failed to apply routes after update: %v", err)
	}

	router.JSON(w, map[string]string{"message": "route updated and applied"})
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/domains/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get domain and access_mode first (need for AdGuard cleanup)
	var domain string
	var accessMode sql.NullString
	err = db.QueryRow("SELECT domain, access_mode FROM domain_routes WHERE id = ?", id).Scan(&domain, &accessMode)
	if err != nil {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}

	// Step 1: Delete AdGuard rewrite only for VPN mode routes
	mode := database.StringFromNullNotEmpty(accessMode, "vpn")
	if mode == "vpn" {
		if err := adguard.DeleteDomainRewrite(domain, s.vpnIP); err != nil {
			router.JSONError(w, "failed to delete DNS rewrite: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Step 2: Delete from database
	result, err := db.Exec("DELETE FROM domain_routes WHERE id = ?", id)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}

	// Step 3: Regenerate Traefik config
	if err := s.applyRoutes(); err != nil {
		router.JSONError(w, "route deleted but failed to update Traefik: "+err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]string{"message": "route deleted and applied"})
}

func (s *Service) handleToggle(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/domains/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, err := db.Exec(`
		UPDATE domain_routes
		SET enabled = NOT enabled, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, id)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}

	// Get new state
	var enabled bool
	if err := db.QueryRow("SELECT enabled FROM domain_routes WHERE id = ?", id).Scan(&enabled); err != nil {
		router.JSONError(w, "failed to get new state", http.StatusInternalServerError)
		return
	}

	// Auto-apply after toggle
	if err := s.applyRoutes(); err != nil {
		log.Printf("Warning: failed to apply routes after toggle: %v", err)
	}

	router.JSON(w, map[string]interface{}{
		"message": "route toggled and applied",
		"enabled": enabled,
	})
}

// handleGetCertificates returns SSL certificate information from acme.json
func (s *Service) handleGetCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := traefik.GetCertificates()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Also get pending/error domains
	pending, err := traefik.GetPendingSSLDomains()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Combine valid certs with pending/error
	allCerts := append(certs, pending...)

	router.JSON(w, map[string]interface{}{
		"certificates": allCerts,
	})
}

// handleGetSystemDomain returns the system SSL domain configured during setup
func (s *Service) handleGetSystemDomain(w http.ResponseWriter, r *http.Request) {
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var sslDomain string
	err = db.QueryRow("SELECT value FROM settings WHERE key = 'ssl_domain'").Scan(&sslDomain)
	if err != nil || sslDomain == "" {
		router.JSON(w, map[string]interface{}{
			"configured": false,
		})
		return
	}

	// Find certificate for this domain
	certs, _ := traefik.GetCertificates()
	var certInfo *traefik.CertificateInfo
	for _, cert := range certs {
		if cert.Domain == sslDomain {
			certInfo = &cert
			break
		}
	}

	router.JSON(w, map[string]interface{}{
		"configured":  true,
		"domain":      sslDomain,
		"certificate": certInfo,
	})
}
