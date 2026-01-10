package router

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/config"
	"api/internal/database"
	"api/internal/helper"
)

// AuthValidator is a function that validates a session token
type AuthValidator func(token string) bool

// authValidator is the registered auth validator
var authValidator AuthValidator

// HandlerFunc is the standard handler function type
type HandlerFunc func(w http.ResponseWriter, r *http.Request)

// ServiceHandlers maps handler names to functions for a service
type ServiceHandlers map[string]HandlerFunc

// Router manages HTTP routing based on configuration
type Router struct {
	mux      *http.ServeMux
	config   *config.Config
	handlers map[string]ServiceHandlers
}

// New creates a new router with the given configuration
func New(cfg *config.Config) *Router {
	return &Router{
		mux:      http.NewServeMux(),
		config:   cfg,
		handlers: make(map[string]ServiceHandlers),
	}
}

// RegisterService registers handlers for a service
func (r *Router) RegisterService(serviceName string, handlers ServiceHandlers) {
	r.handlers[serviceName] = handlers
}

// Build builds the router based on configuration and registered handlers
func (r *Router) Build() http.Handler {
	// Group endpoints by actual pattern (after truncating path params)
	actualPatterns := make(map[string][]routeHandler)

	for serviceName, svcConfig := range r.config.Services {
		if !svcConfig.Enabled {
			log.Printf("Service %s is disabled, skipping", serviceName)
			continue
		}

		handlers, ok := r.handlers[serviceName]
		if !ok {
			log.Printf("Warning: No handlers registered for service %s", serviceName)
			continue
		}

		for _, endpoint := range svcConfig.Endpoints {
			handler, ok := handlers[endpoint.Handler]
			if !ok {
				log.Printf("Warning: Handler %s not found for %s%s", endpoint.Handler, svcConfig.Prefix, endpoint.Path)
				continue
			}

			fullPattern := svcConfig.Prefix + endpoint.Path
			// Get actual pattern for mux registration
			actualPattern := fullPattern
			if strings.Contains(fullPattern, "{") {
				actualPattern = fullPattern[:strings.Index(fullPattern, "{")]
			}

			actualPatterns[actualPattern] = append(actualPatterns[actualPattern], routeHandler{
				fullPattern: fullPattern,
				methods:     endpoint.Methods,
				handler:     handler,
			})
			log.Printf("Registered: %s %v -> %s", fullPattern, endpoint.Methods, endpoint.Handler)
		}
	}

	// Register combined handlers for each actual pattern
	for actualPattern, handlers := range actualPatterns {
		r.registerCombinedEndpointV2(actualPattern, handlers)
	}

	// Add API schema endpoint
	r.mux.HandleFunc("/api/schema", r.handleAPIInfo)
	r.mux.HandleFunc("/health", r.handleHealth)

	return r.applyMiddleware(r.mux)
}

// routeHandler holds method-handler pairs with full pattern
type routeHandler struct {
	fullPattern string
	methods     []string
	handler     HandlerFunc
}

// registerCombinedEndpointV2 registers multiple handlers for a single actual path pattern
func (r *Router) registerCombinedEndpointV2(actualPattern string, handlers []routeHandler) {
	r.mux.HandleFunc(actualPattern, func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Find matching handler based on path and method
		path := req.URL.Path
		for _, rh := range handlers {
			// Check if path matches the full pattern
			if r.pathMatches(path, rh.fullPattern) && r.methodAllowed(req.Method, rh.methods) {
				rh.handler(w, req)
				return
			}
		}

		// Try method matching without strict path match for parameterized routes
		for _, rh := range handlers {
			if r.methodAllowed(req.Method, rh.methods) {
				rh.handler(w, req)
				return
			}
		}

		JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
}

// pathMatches checks if a request path matches a pattern (with {param} support)
func (r *Router) pathMatches(reqPath, pattern string) bool {
	// Exact match
	if reqPath == pattern {
		return true
	}

	// Pattern with parameters
	if !strings.Contains(pattern, "{") {
		return reqPath == pattern
	}

	// Split into parts
	reqParts := strings.Split(strings.Trim(reqPath, "/"), "/")
	patParts := strings.Split(strings.Trim(pattern, "/"), "/")

	if len(reqParts) != len(patParts) {
		return false
	}

	for i, pat := range patParts {
		if strings.HasPrefix(pat, "{") && strings.HasSuffix(pat, "}") {
			continue // Parameter matches anything
		}
		if pat != reqParts[i] {
			return false
		}
	}

	return true
}

// methodAllowed checks if the request method is in the allowed list
func (r *Router) methodAllowed(method string, allowed []string) bool {
	if method == "OPTIONS" {
		return true
	}
	for _, m := range allowed {
		if m == method {
			return true
		}
	}
	return false
}

// SetAuthValidator sets the auth validator function
func SetAuthValidator(validator AuthValidator) {
	authValidator = validator
}

// applyMiddleware wraps the handler with configured middleware
func (r *Router) applyMiddleware(handler http.Handler) http.Handler {
	h := handler

	// Apply auth middleware (must be before logging to reject early)
	h = r.authMiddleware(h)

	// Apply rate limiting middleware
	if r.config.Middleware.RateLimit.Enabled {
		h = r.rateLimitMiddleware(h)
	}

	// Apply body size limit middleware
	h = r.bodySizeLimitMiddleware(h)

	// Apply logging middleware with request IDs
	if r.config.Middleware.Logging.Enabled {
		h = r.loggingMiddleware(h)
	}

	// Apply security headers middleware (CSP, etc.)
	h = r.securityHeadersMiddleware(h)

	// Apply CORS middleware
	if r.config.Middleware.CORS.Enabled {
		h = r.corsMiddleware(h)
	}

	return h
}

// bodySizeLimitMiddleware limits request body size to prevent memory exhaustion
func (r *Router) bodySizeLimitMiddleware(next http.Handler) http.Handler {
	const maxBodySize = 10 * 1024 * 1024 // 10MB

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Body != nil {
			req.Body = http.MaxBytesReader(w, req.Body, maxBodySize)
		}
		next.ServeHTTP(w, req)
	})
}

// authMiddleware checks for valid session token on protected routes
func (r *Router) authMiddleware(next http.Handler) http.Handler {
	// Public path prefixes (any path starting with these is public)
	publicPrefixes := []string{
		"/api/setup/",
		"/api/auth/login",
	}

	// Exact public paths
	publicExact := []string{
		"/health",
		"/api",
		"/api/",
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path

		// Allow OPTIONS requests (CORS preflight)
		if req.Method == "OPTIONS" {
			next.ServeHTTP(w, req)
			return
		}

		// Check exact matches
		for _, exact := range publicExact {
			if path == exact {
				next.ServeHTTP(w, req)
				return
			}
		}

		// Check prefix matches
		for _, prefix := range publicPrefixes {
			if strings.HasPrefix(path, prefix) {
				next.ServeHTTP(w, req)
				return
			}
		}

		// Skip auth if no validator is set (e.g., during initial setup)
		if authValidator == nil {
			next.ServeHTTP(w, req)
			return
		}

		// Extract token from Authorization header or cookie
		token := helper.ExtractBearerToken(req)
		if token == "" {
			JSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate token
		if !authValidator(token) {
			JSONError(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, req)
	})
}

// corsMiddleware adds CORS headers
func (r *Router) corsMiddleware(next http.Handler) http.Handler {
	cors := r.config.Middleware.CORS
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		origin := "*"
		if len(cors.AllowOrigins) > 0 && cors.AllowOrigins[0] != "*" {
			origin = cors.AllowOrigins[0]
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(cors.AllowMethods, ", "))
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(cors.AllowHeaders, ", "))

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, req)
	})
}

// generateRequestID creates a unique request identifier
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}

// loggingMiddleware logs requests with request IDs
func (r *Router) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		requestID := generateRequestID()

		// Add request ID to response headers
		w.Header().Set("X-Request-ID", requestID)

		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, req)

		clientIP := helper.GetClientIP(req)

		if r.config.Middleware.Logging.Format == "json" {
			log.Printf(`{"request_id":"%s","method":"%s","path":"%s","status":%d,"duration":"%s","client_ip":"%s"}`,
				requestID, req.Method, req.URL.Path, wrapped.statusCode, time.Since(start), clientIP)
		} else {
			log.Printf("[%s] %s %s %s %d %s", requestID, clientIP, req.Method, req.URL.Path, wrapped.statusCode, time.Since(start))
		}
	})
}


// securityHeadersMiddleware adds security headers including CSP
func (r *Router) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Content Security Policy - restrictive by default for API
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// XSS protection (legacy but still useful)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy (disable unnecessary browser features)
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, req)
	})
}

// Rate limiter state
var (
	rateLimitBuckets = make(map[string]*rateLimitBucket)
	rateLimitMu      sync.RWMutex
)

type rateLimitBucket struct {
	tokens     float64
	lastUpdate time.Time
}

// Cleanup stale rate limit entries to prevent unbounded memory growth
func init() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			rateLimitMu.Lock()
			cutoff := time.Now().Add(-5 * time.Minute)
			for ip, bucket := range rateLimitBuckets {
				if bucket.lastUpdate.Before(cutoff) {
					delete(rateLimitBuckets, ip)
				}
			}
			rateLimitMu.Unlock()
		}
	}()
}

// rateLimitMiddleware implements token bucket rate limiting per IP
func (r *Router) rateLimitMiddleware(next http.Handler) http.Handler {
	rps := r.config.Middleware.RateLimit.RequestsPerSecond
	if rps <= 0 {
		rps = 100 // Default: 100 requests per second
	}
	burstSize := float64(rps * 2) // Allow burst of 2x rate

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		clientIP := helper.GetClientIP(req)

		// Skip rate limiting for health checks
		if req.URL.Path == "/health" {
			next.ServeHTTP(w, req)
			return
		}

		now := time.Now()

		rateLimitMu.Lock()
		bucket, exists := rateLimitBuckets[clientIP]
		if !exists {
			bucket = &rateLimitBucket{tokens: burstSize, lastUpdate: now}
			rateLimitBuckets[clientIP] = bucket
		}

		// Refill tokens based on elapsed time
		elapsed := now.Sub(bucket.lastUpdate).Seconds()
		bucket.tokens += elapsed * float64(rps)
		if bucket.tokens > burstSize {
			bucket.tokens = burstSize
		}
		bucket.lastUpdate = now

		// Check if request can proceed
		if bucket.tokens < 1 {
			rateLimitMu.Unlock()
			w.Header().Set("Retry-After", "1")
			JSONError(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		bucket.tokens--
		rateLimitMu.Unlock()

		next.ServeHTTP(w, req)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleAPIInfo returns information about available endpoints
func (r *Router) handleAPIInfo(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	info := map[string]interface{}{
		"version":  r.config.Version,
		"services": make(map[string]interface{}),
	}

	for name, svc := range r.config.Services {
		if !svc.Enabled {
			continue
		}

		endpoints := make([]map[string]interface{}, 0, len(svc.Endpoints))
		for _, ep := range svc.Endpoints {
			endpoints = append(endpoints, map[string]interface{}{
				"path":        svc.Prefix + ep.Path,
				"methods":     ep.Methods,
				"description": ep.Description,
			})
		}

		info["services"].(map[string]interface{})[name] = map[string]interface{}{
			"prefix":    svc.Prefix,
			"endpoints": endpoints,
		}
	}

	if err := json.NewEncoder(w).Encode(info); err != nil {
		log.Printf("Error encoding info response: %v", err)
	}
}

// HealthCheck represents a single health check result
type HealthCheck struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Latency string `json:"latency,omitempty"`
}

// HealthResponse represents the complete health status
type HealthResponse struct {
	Status    string                 `json:"status"`
	Timestamp string                 `json:"timestamp"`
	Checks    map[string]HealthCheck `json:"checks"`
}

// handleHealth returns comprehensive health status
func (r *Router) handleHealth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    make(map[string]HealthCheck),
	}

	// Check database
	dbCheck := checkDatabase()
	response.Checks["database"] = dbCheck
	if dbCheck.Status != "ok" {
		response.Status = "degraded"
	}

	// Check Headscale connectivity (if configured)
	hsCheck := checkHeadscale()
	response.Checks["headscale"] = hsCheck
	if hsCheck.Status == "error" && response.Status == "ok" {
		response.Status = "degraded"
	}

	// Set appropriate HTTP status
	statusCode := http.StatusOK
	if response.Status != "ok" {
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

// checkDatabase verifies database connectivity
func checkDatabase() HealthCheck {
	start := time.Now()
	db, err := database.GetDB()
	if err != nil {
		return HealthCheck{Status: "error", Message: "database not initialized"}
	}

	// Simple ping query
	var result int
	err = db.QueryRow("SELECT 1").Scan(&result)
	latency := time.Since(start)

	if err != nil {
		return HealthCheck{Status: "error", Message: err.Error(), Latency: latency.String()}
	}

	return HealthCheck{Status: "ok", Latency: latency.String()}
}

// checkHeadscale verifies Headscale API connectivity
func checkHeadscale() HealthCheck {
	start := time.Now()

	// Try to get Headscale config
	resp, err := helper.HeadscaleGet("/user")
	latency := time.Since(start)

	if err != nil {
		// Not configured is not an error - it's expected during setup
		if strings.Contains(err.Error(), "not configured") {
			return HealthCheck{Status: "unconfigured", Message: "headscale not configured yet"}
		}
		return HealthCheck{Status: "error", Message: err.Error(), Latency: latency.String()}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return HealthCheck{Status: "error", Message: "API returned " + resp.Status, Latency: latency.String()}
	}

	return HealthCheck{Status: "ok", Latency: latency.String()}
}

// ExtractPathParam extracts a path parameter from the URL
func ExtractPathParam(r *http.Request, prefix string) string {
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// ExtractPathParamFull extracts the full remaining path after prefix (for CIDR IPs like 0.0.0.0/8)
func ExtractPathParamFull(r *http.Request, prefix string) string {
	path := strings.TrimPrefix(r.URL.Path, prefix)
	return strings.Trim(path, "/")
}

// JSON sends a JSON response with 200 OK status
func JSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// JSONWithStatus sends a JSON response with a custom status code
func JSONWithStatus(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// JSONError sends a JSON error response
func JSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}

// PaginationParams holds parsed pagination parameters
type PaginationParams struct {
	Limit  int
	Offset int
}

// ParsePagination extracts limit and offset from URL query parameters
// with sensible defaults and validation. Max limit is 1000.
func ParsePagination(r *http.Request, defaultLimit int) PaginationParams {
	const maxLimit = 1000

	p := PaginationParams{
		Limit:  defaultLimit,
		Offset: 0,
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			p.Limit = parsed
		}
	}

	if p.Limit > maxLimit {
		p.Limit = maxLimit
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			p.Offset = parsed
		}
	}

	return p
}

// DecodeJSON decodes JSON from request body into the provided value
func DecodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// DecodeJSONOrError decodes JSON and sends error response if failed
// Returns true if decode succeeded, false if error was sent
func DecodeJSONOrError(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		JSONError(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// ExtractPathSegment extracts a specific segment from URL path after prefix
// segmentIndex 0 = first segment after prefix
func ExtractPathSegment(r *http.Request, prefix string, segmentIndex int) string {
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if segmentIndex >= 0 && segmentIndex < len(parts) {
		return parts[segmentIndex]
	}
	return ""
}

// ExtractPathParamInt extracts a path parameter and converts to int
// Returns the value and true if successful, or 0 and false if not
func ExtractPathParamInt(r *http.Request, prefix string) (int64, bool) {
	param := ExtractPathParam(r, prefix)
	if param == "" {
		return 0, false
	}
	val, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		return 0, false
	}
	return val, true
}

// QueryParam gets a query parameter with optional default value
func QueryParam(r *http.Request, name, defaultValue string) string {
	if val := r.URL.Query().Get(name); val != "" {
		return val
	}
	return defaultValue
}

// QueryParamInt gets a query parameter as int with optional default value
func QueryParamInt(r *http.Request, name string, defaultValue int) int {
	if val := r.URL.Query().Get(name); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// ParseIDOrError parses a string ID and sends JSON error response if invalid
// Returns the parsed ID and true if successful, or 0 and false if error was sent
func ParseIDOrError(w http.ResponseWriter, idStr string) (int, bool) {
	if idStr == "" {
		JSONError(w, "id required", http.StatusBadRequest)
		return 0, false
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		JSONError(w, "invalid id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}
