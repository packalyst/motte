package router

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/config"
	"api/internal/database"
	"api/internal/helper"
)

// Principal is the authenticated operator behind a request, resolved from the session by the
// auth service. The auth middleware injects it into the request context for both role
// enforcement (here) and handlers that need the caller's identity/scope (via CurrentUser).
type Principal struct {
	UserID      int64
	Username    string
	Role        string
	ScopeKind   string
	ScopeValues string
	Locked      bool // session is idle-locked server-side; only unlock/logout/me/lock are allowed
}

// lockAllowedPath lists the only endpoints an idle-locked session may reach: enough to re-auth
// (unlock), observe the locked state (me), lock again, or get out (logout). Everything else is
// refused with 423 until the session is unlocked.
func lockAllowedPath(p string) bool {
	switch p {
	case "/api/auth/unlock", "/api/auth/lock", "/api/auth/logout", "/api/auth/me":
		return true
	}
	return false
}

// AuthResolver validates a session token and returns the principal it belongs to.
type AuthResolver func(token string) (*Principal, bool)

// authResolver is the registered auth resolver.
var authResolver AuthResolver

// principalCtxKey keys the Principal in a request context.
type principalCtxKey struct{}

// CurrentUser returns the authenticated principal for a request, or nil on a public route.
func CurrentUser(r *http.Request) *Principal {
	p, _ := r.Context().Value(principalCtxKey{}).(*Principal)
	return p
}

// ContextWithPrincipal returns ctx carrying p. The auth middleware uses it to attach the
// resolved principal; it is also the seam tests use to simulate an authenticated caller.
func ContextWithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// roleRank mirrors auth's role ladder (auth is the source of truth). The router only needs the
// ordering to compare an endpoint's configured min_role against the caller's role; keeping the
// four strings here avoids an import cycle (auth imports router). 0 (unknown) fails closed.
var roleRank = map[string]int{"viewer": 1, "operator": 2, "admin": 3, "owner": 4}

// defaultRoleForMethod is the min role when an endpoint sets no explicit min_role: reads need
// viewer, mutations need admin (least privilege — operational writes are opted down per route).
func defaultRoleForMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "viewer"
	default:
		return "admin"
	}
}

// roleSatisfies reports whether have-role meets the min-role requirement.
func roleSatisfies(have, min string) bool {
	h, m := roleRank[have], roleRank[min]
	return h > 0 && m > 0 && h >= m
}

// PanelVersion is the build commit (short sha), set by main at startup and surfaced on
// /api/schema so the UI can show which build is running.
var PanelVersion = "dev"

// PanelBranch is the git branch this panel was built from, set by main at startup. Used by
// the panel update-check to compare against the right branch tip on the source repo.
var PanelBranch = ""

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
				minRole:     endpoint.MinRole,
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
	r.mux.HandleFunc("/api/manifest.json", r.handleManifest)
	r.mux.HandleFunc("/health", r.handleHealth)

	return r.applyMiddleware(r.mux)
}

// routeHandler holds method-handler pairs with full pattern
type routeHandler struct {
	fullPattern string
	methods     []string
	handler     HandlerFunc
	minRole     string // least-privileged role allowed; "" → defaultRoleForMethod
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
				if !r.authorizeRole(w, req, rh.minRole) {
					return
				}
				rh.handler(w, req)
				return
			}
		}

		// Nothing strictly matched. NEVER dispatch a handler whose path did not
		// match — that let a malformed URL (e.g. /api/wg/peers/5/typo) silently
		// fire an unrelated action. Distinguish 405 (a route exists at this path
		// but not for this method) from 404 (no such route).
		for _, rh := range handlers {
			if r.pathMatches(path, rh.fullPattern) {
				JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
		}
		JSONError(w, "Not found", http.StatusNotFound)
	})
}

// authorizeRole enforces the matched endpoint's minimum role against the request's principal.
// A nil principal means the auth middleware classified the path as public (it never injects
// one there), so no role is required. Otherwise the caller's role must meet minRole, or the
// endpoint's method default when minRole is unset.
func (r *Router) authorizeRole(w http.ResponseWriter, req *http.Request, minRole string) bool {
	p := CurrentUser(req)
	if p == nil {
		return true // public route
	}
	required := minRole
	if required == "" {
		required = defaultRoleForMethod(req.Method)
	}
	if !roleSatisfies(p.Role, required) {
		JSONError(w, "insufficient role for this action", http.StatusForbidden)
		return false
	}
	return true
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

	// Trailing catch-all: a final "{name...}" matches one or more remaining
	// segments (e.g. /api/hook/{keys...} matches /api/hook/k1/k2/k3). Only
	// patterns explicitly ending in "...}" use this; every other route is
	// unaffected.
	if n := len(patParts); n > 0 && strings.HasPrefix(patParts[n-1], "{") && strings.HasSuffix(patParts[n-1], "...}") {
		if len(reqParts) < n {
			return false
		}
		for i := 0; i < n-1; i++ {
			pat := patParts[i]
			if strings.HasPrefix(pat, "{") && strings.HasSuffix(pat, "}") {
				continue
			}
			if pat != reqParts[i] {
				return false
			}
		}
		return true
	}

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

// SetAuthResolver sets the auth resolver function.
func SetAuthResolver(resolver AuthResolver) {
	authResolver = resolver
}

// StepUpFunc re-authenticates the caller of a sensitive, session-authorized request for a
// destructive action. It returns true when step-up passed; on failure it writes a 428 response and
// returns false. Registered by the auth service (SetStepUpFunc) so packages like wireguard and
// headscale can gate deletes without importing auth, which would create an import cycle.
type StepUpFunc func(w http.ResponseWriter, r *http.Request) bool

var stepUpFn StepUpFunc

// SetStepUpFunc registers the step-up re-auth check used by StepUp.
func SetStepUpFunc(fn StepUpFunc) {
	stepUpFn = fn
}

// StepUp runs the registered step-up check. When none is registered it allows the action
// (fail-open to pre-step-up behavior) so a mis-wired build never hard-locks a destructive action.
func StepUp(w http.ResponseWriter, r *http.Request) bool {
	if stepUpFn == nil {
		return true
	}
	return stepUpFn(w, r)
}

// applyMiddleware wraps the handler with configured middleware
func (r *Router) applyMiddleware(handler http.Handler) http.Handler {
	h := handler

	// Apply auth middleware (must be before logging to reject early)
	h = r.authMiddleware(h)

	// Apply CSRF origin check (wraps auth so a forged cross-origin cookie write is refused
	// before the session is even validated).
	h = r.csrfMiddleware(h)

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
		"/api/auth/passkeys/login/", // passwordless passkey login (begin/finish); no session yet
		"/api/restart/",             // public tunnel-rotation trigger (its own per-key secret)
		"/api/hook/",                // public webhook trigger (its own per-webhook keys)
	}

	// Exact public paths
	publicExact := []string{
		"/health",
		"/api",
		"/api/",
		"/api/manifest.json",
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

		// Auth is required but unavailable: the resolver is only registered when the
		// auth service is enabled AND initializes successfully (see cmd/main.go). A nil
		// resolver therefore means auth is disabled or failed to init at boot — fail
		// CLOSED for protected paths rather than serving them with no authentication.
		// Public paths (login, setup, health) are matched above, so this can't lock out
		// the setup wizard or login.
		if authResolver == nil {
			JSONError(w, "Authentication unavailable", http.StatusServiceUnavailable)
			return
		}

		// Extract token from Authorization header or cookie
		token := helper.SessionToken(req)
		if token == "" {
			JSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate token and resolve the principal (identity + role + scope).
		principal, ok := authResolver(token)
		if !ok || principal == nil {
			JSONError(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}

		// An idle-locked session is refused with 423 everywhere except the unlock/logout/me/lock
		// endpoints. This is what makes the idle lock a real server boundary: a page refresh (or
		// any direct API call) stays locked until the user re-authenticates, instead of the lock
		// being a client-only overlay that F5 clears.
		if principal.Locked && !lockAllowedPath(path) {
			JSONError(w, "Session locked", http.StatusLocked)
			return
		}

		// Carry the principal so per-route role enforcement and handlers can read it. Role
		// authorization happens at dispatch (registerCombinedEndpointV2), where the matched
		// endpoint's min_role is known.
		req = req.WithContext(ContextWithPrincipal(req.Context(), principal))
		next.ServeHTTP(w, req)
	})
}

// csrfMiddleware refuses state-changing requests that carry the ambient session cookie but
// originate from another site. Moving the session into a cookie (HttpOnly, for XSS safety)
// reintroduces CSRF exposure; SameSite=Strict on the cookie is the browser-side defense and
// this is the server-side one. It applies ONLY to cookie-authenticated requests: a client
// using an explicit Authorization header carries no ambient authority and is exempt (so
// scripted/CLI access and the login/setup bootstrap keep working). A missing Origin/Referer
// on a cookie-bearing write is treated as a refusal, not a pass.
func (r *Router) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// Safe methods never change state.
		default:
			if helper.HasSessionCookie(req) && !sameOrigin(req) {
				JSONError(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}

// sameOrigin reports whether the request's Origin (or Referer fallback) host matches the host
// the browser addressed. Behind Traefik the external host arrives in X-Forwarded-Host.
func sameOrigin(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		origin = req.Header.Get("Referer")
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}
	return strings.EqualFold(u.Host, host)
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
		logPath := helper.RedactSecretPath(req.URL.Path)

		if r.config.Middleware.Logging.Format == "json" {
			log.Printf(`{"request_id":"%s","method":"%s","path":"%s","status":%d,"duration":"%s","client_ip":"%s"}`,
				requestID, req.Method, logPath, wrapped.statusCode, time.Since(start), clientIP)
		} else {
			log.Printf("[%s] %s %s %s %d %s", requestID, clientIP, req.Method, logPath, wrapped.statusCode, time.Since(start))
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
		"version":       r.config.Version, // API/config schema version
		"panel_version": PanelVersion,     // build version (git describe)
		"services":      make(map[string]interface{}),
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

// handleManifest returns a dynamic PWA manifest with domain-specific name
func (r *Router) handleManifest(w http.ResponseWriter, req *http.Request) {
	sslDomain := helper.GetEnvOptional("SSL_DOMAIN", "")
	if sslDomain == "" {
		http.NotFound(w, req)
		return
	}

	// Build manifest with domain-specific name
	// short_name is used by iOS for home screen icon (keep it short)
	manifest := map[string]interface{}{
		"name":             "Wire Panel - " + sslDomain,
		"short_name":       sslDomain,
		"description":      "WireGuard & Headscale Admin Panel",
		"start_url":        "/",
		"display":          "standalone",
		"background_color": "#16161a",
		"theme_color":      "#16161a",
		"icons": []map[string]interface{}{
			{
				"src":     "/icon-192.png",
				"sizes":   "192x192",
				"type":    "image/png",
				"purpose": "any",
			},
			{
				"src":     "/icon-512.png",
				"sizes":   "512x512",
				"type":    "image/png",
				"purpose": "any maskable",
			},
			{
				"src":   "/icon.svg",
				"sizes": "any",
				"type":  "image/svg+xml",
			},
		},
	}

	w.Header().Set("Content-Type", "application/manifest+json")
	if err := json.NewEncoder(w).Encode(manifest); err != nil {
		log.Printf("Error encoding manifest: %v", err)
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
