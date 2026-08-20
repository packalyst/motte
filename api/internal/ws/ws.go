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
	// Upgrade to WebSocket first; authentication happens via the first message.
	// The token is never accepted in the URL query — that would leak it into
	// proxy/access logs and browser history.
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	authSvc := auth.GetService()
	if authSvc == nil {
		conn.WriteMessage(1, []byte(`{"type":"error","error":"Auth service unavailable"}`))
		conn.Close()
		return
	}

	var user *auth.User

	// Authenticate via the first message: {"action":"auth","token":"..."}.
	conn.SetReadDeadline(time.Now().Add(helper.WebSocketReadTimeout))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{}) // Reset deadline

	var authMsg struct {
		Action string `json:"action"`
		Token  string `json:"token"`
	}
	if err := json.Unmarshal(msg, &authMsg); err != nil || authMsg.Action != "auth" || authMsg.Token == "" {
		conn.WriteMessage(1, []byte(`{"type":"error","error":"Invalid auth message"}`))
		conn.Close()
		return
	}

	user, err = authSvc.ValidateSession(authMsg.Token)
	if err != nil {
		conn.WriteMessage(1, []byte(`{"type":"error","error":"Invalid or expired token"}`))
		conn.Close()
		return
	}

	// Create client
	client := NewClient(s.hub, conn, user.ID, user.Username)

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
