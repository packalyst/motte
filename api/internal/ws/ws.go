package ws

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"api/internal/auth"
	"api/internal/config"
	"api/internal/helper"
	"api/internal/routines"

	"github.com/gorilla/websocket"
)

// Service manages WebSocket connections
type Service struct {
	hub      *Hub
	upgrader websocket.Upgrader
}

// Global serviceInstance for broadcasting from other packages
var serviceInstance *Service

// New creates a new WebSocket service
func New() *Service {
	// Initialize config values
	initConfig()

	cfg := config.GetWebSocketConfig()
	hub := newHub(cfg.BroadcastBufferSize)

	// Start hub in background
	go hub.Run()
	routines.RegisterDaemon("ws-hub", "WebSocket hub: fan-out of live updates to connected clients")

	s := &Service{
		hub: hub,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  cfg.ReadBufferSize,
			WriteBufferSize: cfg.WriteBufferSize,
			CheckOrigin:     checkOrigin,
		},
	}

	serviceInstance = s
	return s
}

// checkOrigin validates WebSocket connection origins: the panel's own, or one listed explicitly
// in the CORS config. The CORS "*" doesn't count here: the session cookie rides along on any
// same-site upgrade, so a sibling site (another subdomain or port) could otherwise read the live
// channels as the signed-in user.
func checkOrigin(r *http.Request) bool {
	if helper.SameOrigin(r) {
		return true
	}
	origin := r.Header.Get("Origin")

	// Get allowed origins from CORS config
	cfg := config.Get()
	if cfg == nil {
		log.Printf("WebSocket: config not available, rejecting origin: %s", origin)
		return false
	}

	allowedOrigins := cfg.Middleware.CORS.AllowOrigins

	// Parse origin URL
	originURL, err := url.Parse(origin)
	if err != nil {
		log.Printf("WebSocket: invalid origin URL: %s", origin)
		return false
	}

	// Check against allowed origins
	for _, allowed := range allowedOrigins {
		allowedURL, err := url.Parse(allowed)
		if err != nil {
			continue
		}

		// Compare scheme and host (ignoring path)
		if strings.EqualFold(originURL.Scheme, allowedURL.Scheme) &&
			strings.EqualFold(originURL.Host, allowedURL.Host) {
			return true
		}
	}

	log.Printf("WebSocket: origin not allowed: %s (allowed: %v)", origin, allowedOrigins)
	return false
}

// HandleWebSocket handles WebSocket upgrade requests. The session is checked on the upgrade
// request itself (the HttpOnly cookie, or Bearer), before anything is accepted: no credential, or a
// bad one, is refused at the HTTP layer and the socket never opens.
func (s *Service) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	authSvc := auth.GetService()
	if authSvc == nil {
		http.Error(w, "auth service unavailable", http.StatusServiceUnavailable)
		return
	}

	// Authenticate the handshake BEFORE upgrading: browsers attach the HttpOnly session cookie to
	// the WS upgrade, non-browser clients may send Bearer (helper.SessionToken reads both). No
	// credential, or a bad one, is refused at the HTTP layer, so nothing is read from a stranger.
	// The token is never read from the URL query (that would leak into proxy/access logs and
	// browser history).
	token := helper.SessionToken(r)
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	user, verr := authSvc.ValidateSession(token)
	if verr != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Idle-locked sessions get no live data either: refuse the upgrade, mirroring the
	// router's 423 on HTTP (see router.authMiddleware / lockAllowedPath).
	if authSvc.IsSessionLocked(token) {
		http.Error(w, "session locked", http.StatusLocked)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Create client
	client := NewClient(s.hub, conn, user.ID, user.Username, user.Role, user.ScopeKind, user.ScopeValues)
	client.stillValid = func() bool {
		u, err := authSvc.ValidateSession(token)
		return err == nil && !authSvc.IsSessionLocked(token) && u.ID == user.ID && u.Role == user.Role &&
			u.ScopeKind == user.ScopeKind && u.ScopeValues == user.ScopeValues
	}

	// Register client: at most MaxWSClientsPerUser live sockets per user.
	if !s.hub.admit(client) {
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "too many live connections"))
		conn.Close()
		return
	}

	// Send initial auth info to client
	client.sendInitMessage(user)

	// Start read/write pumps
	go client.WritePump()
	go client.ReadPump()
}

// Broadcast sends a message to all clients subscribed to a channel
// This is the main API for other packages to push updates
func Broadcast(channel string, payload interface{}) {
	if serviceInstance != nil && serviceInstance.hub != nil {
		serviceInstance.hub.Broadcast(channel, payload)
	}
}

// BroadcastFiltered sends a channel message only to subscribers for whom allow() returns true.
func BroadcastFiltered(channel string, payload interface{}, allow func(userID int64, role, scopeKind, scopeValues string) bool) {
	if serviceInstance != nil && serviceInstance.hub != nil {
		serviceInstance.hub.BroadcastFiltered(channel, payload, allow)
	}
}

// BroadcastToUser sends a message to all connected clients of a specific user
func BroadcastToUser(userID int64, channel string, payload interface{}) {
	if serviceInstance != nil && serviceInstance.hub != nil {
		serviceInstance.hub.BroadcastToUser(userID, channel, payload)
	}
}

// ClientCount returns the number of connected clients
func ClientCount() int {
	if serviceInstance != nil && serviceInstance.hub != nil {
		return serviceInstance.hub.ClientCount()
	}
	return 0
}

// ChannelSubscriberCount returns how many clients are subscribed to a channel.
// Used to gate expensive collectors so they do no work when nobody is watching.
func ChannelSubscriberCount(channel string) int {
	if serviceInstance != nil && serviceInstance.hub != nil {
		return serviceInstance.hub.ChannelSubscriberCount(channel)
	}
	return 0
}
