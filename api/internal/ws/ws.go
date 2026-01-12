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
	// Check for token in query string (legacy support) or accept connection for message-based auth
	token := r.URL.Query().Get("token")

	// Upgrade to WebSocket first (auth will happen via message if no token in URL)
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

	// If token in URL (legacy), validate immediately
	// Note: URL tokens are less secure (appear in logs) - prefer message-based auth
	if token != "" {
		user, err = authSvc.ValidateSession(token)
		if err != nil {
			conn.WriteMessage(1, []byte(`{"type":"error","error":"Invalid or expired token"}`))
			conn.Close()
			return
		}
	} else {
		// Wait for auth message (with timeout)
		conn.SetReadDeadline(time.Now().Add(helper.WebSocketReadTimeout))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			conn.Close()
			return
		}
		conn.SetReadDeadline(time.Time{}) // Reset deadline

		// Parse auth message
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
