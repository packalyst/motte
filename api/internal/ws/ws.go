package ws

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// SetService sets the global service serviceInstance
func SetService(s *Service) {
	serviceInstance = s
}

// GetService returns the global service serviceInstance
func GetService() *Service {
	return serviceInstance
}

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

// checkOrigin validates WebSocket connection origins against allowed origins
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// No origin header = same-origin request (e.g., from CLI tools)
		return true
	}

	// Get allowed origins from CORS config
	cfg := config.Get()
	if cfg == nil {
		log.Printf("WebSocket: config not available, rejecting origin: %s", origin)
		return false
	}

	allowedOrigins := cfg.Middleware.CORS.AllowOrigins

	// Check if wildcard is allowed
	for _, allowed := range allowedOrigins {
		if allowed == "*" {
			return true
		}
	}

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

// GetHub returns the hub for external access
func (s *Service) GetHub() *Hub {
	return s.hub
}

// HandleWebSocket handles WebSocket upgrade requests
// Authentication is done via first message after connection (more secure than URL query param)
func (s *Service) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	authSvc := auth.GetService()
	if authSvc == nil {
		http.Error(w, "auth service unavailable", http.StatusServiceUnavailable)
		return
	}

	// Authenticate the handshake BEFORE upgrading whenever the client presents a credential:
	// browsers attach the HttpOnly session cookie to the WS upgrade, non-browser clients may
	// send Bearer (helper.SessionToken reads both). A present-but-invalid credential is
	// refused at the HTTP layer — we never accept the socket for an unauthenticated principal.
	// The token is never read from the URL query (that would leak into proxy/access logs and
	// browser history).
	handshakeToken := helper.SessionToken(r)
	var user *auth.User
	if handshakeToken != "" {
		u, verr := authSvc.ValidateSession(handshakeToken)
		if verr != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Idle-locked sessions get no live data either: refuse the upgrade, mirroring the
		// router's 423 on HTTP (see router.authMiddleware / lockAllowedPath).
		if authSvc.IsSessionLocked(handshakeToken) {
			http.Error(w, "session locked", http.StatusLocked)
			return
		}
		user = u
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	if user == nil {
		// No handshake credential: fall back to first-message auth for clients that cannot
		// present a cookie/Bearer on the upgrade. Fail-closed — the socket carries no data
		// until a valid token arrives within the read deadline.
		// Message shape: {"action":"auth","token":"..."}.
		conn.SetReadDeadline(time.Now().Add(helper.WebSocketReadTimeout))
		_, msg, rerr := conn.ReadMessage()
		if rerr != nil {
			conn.Close()
			return
		}
		conn.SetReadDeadline(time.Time{}) // Reset deadline

		var authMsg struct {
			Action string `json:"action"`
			Token  string `json:"token"`
		}
		if jerr := json.Unmarshal(msg, &authMsg); jerr != nil || authMsg.Action != "auth" || authMsg.Token == "" {
			conn.WriteMessage(1, []byte(`{"type":"error","error":"Invalid auth message"}`))
			conn.Close()
			return
		}
		u, verr := authSvc.ValidateSession(authMsg.Token)
		if verr != nil {
			conn.WriteMessage(1, []byte(`{"type":"error","error":"Invalid or expired token"}`))
			conn.Close()
			return
		}
		if authSvc.IsSessionLocked(authMsg.Token) {
			conn.WriteMessage(1, []byte(`{"type":"error","error":"session locked"}`))
			conn.Close()
			return
		}
		user = u
	}

	// Create client
	client := NewClient(s.hub, conn, user.ID, user.Username, user.Role, user.ScopeKind, user.ScopeValues)

	// Register client
	s.hub.register <- client

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

// BroadcastAll sends a message to all connected clients
func BroadcastAll(channel string, payload interface{}) {
	if serviceInstance != nil && serviceInstance.hub != nil {
		serviceInstance.hub.BroadcastToAll(channel, payload)
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
