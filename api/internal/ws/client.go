package ws

import (
	"encoding/json"
	"log"
	"time"

	"api/internal/config"

	"github.com/gorilla/websocket"
)

// Config values (initialized from config package)
var (
	writeWait      time.Duration
	pongWait       time.Duration
	pingPeriod     time.Duration
	maxMessageSize int64
	sendBufferSize int
	validChannels  map[string]bool
)

// initConfig loads WebSocket settings from config
func initConfig() {
	cfg := config.GetWebSocketConfig()
	writeWait = time.Duration(cfg.WriteWaitSec) * time.Second
	pongWait = time.Duration(cfg.PongWaitSec) * time.Second
	pingPeriod = (pongWait * 9) / 10
	maxMessageSize = cfg.MaxMessageSize
	sendBufferSize = cfg.SendBufferSize

	// Build valid channels map from config
	validChannels = make(map[string]bool)
	for _, ch := range cfg.Channels {
		validChannels[ch] = true
	}
}

// Client represents a WebSocket client connection
type Client struct {
	hub *Hub

	// The websocket connection
	conn *websocket.Conn

	// Buffered channel of outbound messages
	send chan []byte

	// User info from auth
	UserID   int64
	Username string

	// Log streaming state
	logStreamStop chan struct{}
	logContainer  string
}

// NewClient creates a new client
func NewClient(hub *Hub, conn *websocket.Conn, userID int64, username string) *Client {
	return &Client{
		hub:      hub,
		conn:     conn,
		send:     make(chan []byte, sendBufferSize),
		UserID:   userID,
		Username: username,
	}
}

// ReadPump pumps messages from the websocket connection to the hub
func (c *Client) ReadPump() {
	defer func() {
		c.stopLogStream() // Stop any active log stream
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Parse client message
		var msg ClientMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("Invalid client message: %v", err)
			continue
		}

		// Handle subscribe/unsubscribe
		switch msg.Action {
		case "subscribe":
			for _, channel := range msg.Channels {
				if isValidChannel(channel) {
					c.hub.Subscribe(c, channel)
					// Send current data immediately on subscribe
					switch channel {
					case "general_info":
						c.sendCurrentNodeStats()
					case "docker":
						c.sendCurrentDockerContainers()
					case "docker_logs":
						c.startLogStream(msg.Container)
					case "stats":
						c.sendCurrentOverviewStats()
					}
				}
			}
		case "unsubscribe":
			for _, channel := range msg.Channels {
				c.hub.Unsubscribe(c, channel)
				if channel == "docker_logs" {
					c.stopLogStream()
				}
			}
		}
	}
}

// WritePump pumps messages from the hub to the websocket connection
func (c *Client) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Batch any queued messages
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// isValidChannel checks if a channel name is allowed
func isValidChannel(channel string) bool {
	return validChannels[channel]
}

// sendMessage sends a message to this client (non-blocking)
func (c *Client) sendMessage(msgType string, payload interface{}) {
	msg := &Message{Type: msgType, Payload: payload}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	select {
	case c.send <- data:
	default:
		// Buffer full, skip
	}
}

// sendCurrentNodeStats sends current node stats to this client immediately
func (c *Client) sendCurrentNodeStats() {
	c.sendMessage("general_info", map[string]interface{}{
		"event": "stats",
		"data":  GetCurrentNodeStats(),
	})
}

// sendCurrentDockerContainers sends current docker containers to this client immediately
func (c *Client) sendCurrentDockerContainers() {
	containers := GetCurrentDockerContainers()
	if containers == nil {
		return
	}
	c.sendMessage("docker", map[string]interface{}{"containers": containers})
}

// sendCurrentOverviewStats sends current overview stats to this client immediately
func (c *Client) sendCurrentOverviewStats() {
	stats := GetCurrentOverviewStats()
	if stats == nil {
		return
	}
	c.sendMessage("stats", stats)
}

// sendInitMessage sends initial auth info when client connects
func (c *Client) sendInitMessage(user interface{}) {
	c.sendMessage("init", map[string]interface{}{"valid": true, "user": user})
}

// startLogStream starts streaming logs for a container
func (c *Client) startLogStream(containerName string) {
	if containerName == "" {
		log.Printf("Client %s: docker_logs subscribe without container name", c.Username)
		return
	}

	// Stop any existing stream
	c.stopLogStream()

	streamer := GetDockerLogStreamer()
	if streamer == nil {
		log.Printf("Client %s: docker log streamer not available", c.Username)
		return
	}

	c.logStreamStop = make(chan struct{})
	c.logContainer = containerName

	log.Printf("Client %s: starting log stream for container %s", c.Username, containerName)

	go func() {
		err := streamer.StreamLogs(containerName, func(entry DockerLogEntry) {
			c.sendMessage("docker_logs", entry)
		}, c.logStreamStop)

		if err != nil {
			log.Printf("Client %s: log stream error for %s: %v", c.Username, containerName, err)
		}
	}()
}

// stopLogStream stops any active log stream
func (c *Client) stopLogStream() {
	if c.logStreamStop != nil {
		close(c.logStreamStop)
		c.logStreamStop = nil
		if c.logContainer != "" {
			log.Printf("Client %s: stopped log stream for container %s", c.Username, c.logContainer)
			c.logContainer = ""
		}
	}
}
