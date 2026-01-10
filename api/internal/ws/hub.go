package ws

import (
	"encoding/json"
	"log"
	"sync"
)

// Hub manages WebSocket connections and message broadcasting
type Hub struct {
	// Registered clients by user ID
	clients map[*Client]bool

	// Channel-based subscriptions: channel -> clients
	subscriptions map[string]map[*Client]bool

	// Inbound messages from clients
	broadcast chan *Message

	// Register requests from clients
	register chan *Client

	// Unregister requests from clients
	unregister chan *Client

	// Mutex for thread-safe operations
	mu sync.RWMutex
}

// Message represents a WebSocket message
type Message struct {
	Type    string      `json:"type"`    // Channel: "stats", "nodes", "traffic", "docker", etc.
	Payload interface{} `json:"payload"` // Data payload
}

// ClientMessage represents an incoming message from client
type ClientMessage struct {
	Action    string   `json:"action"`    // "subscribe", "unsubscribe"
	Channels  []string `json:"channels"`  // Channels to sub/unsub
	Container string   `json:"container"` // Container name for docker_logs
}

// newHub creates a new Hub instance with configurable buffer size
func newHub(broadcastBufferSize int) *Hub {
	return &Hub{
		clients:       make(map[*Client]bool),
		subscriptions: make(map[string]map[*Client]bool),
		broadcast:     make(chan *Message, broadcastBufferSize),
		register:      make(chan *Client),
		unregister:    make(chan *Client),
	}
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("WebSocket client connected (user: %s, total: %d)", client.Username, len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)

				// Remove from all subscriptions
				for channel := range h.subscriptions {
					delete(h.subscriptions[channel], client)
				}
			}
			h.mu.Unlock()
			log.Printf("WebSocket client disconnected (user: %s, total: %d)", client.Username, len(h.clients))

		case message := <-h.broadcast:
			h.broadcastToChannel(message)
		}
	}
}

// Subscribe adds a client to a channel
func (h *Hub) Subscribe(client *Client, channel string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.subscriptions[channel] == nil {
		h.subscriptions[channel] = make(map[*Client]bool)
	}
	h.subscriptions[channel][client] = true
	log.Printf("Client %s subscribed to channel: %s", client.Username, channel)
}

// Unsubscribe removes a client from a channel
func (h *Hub) Unsubscribe(client *Client, channel string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.subscriptions[channel] != nil {
		delete(h.subscriptions[channel], client)
	}
}

// Broadcast sends a message to all clients subscribed to the channel
func (h *Hub) Broadcast(channel string, payload interface{}) {
	h.broadcast <- &Message{
		Type:    channel,
		Payload: payload,
	}
}

// BroadcastToAll sends a message to all connected clients
func (h *Hub) BroadcastToAll(channel string, payload interface{}) {
	msg := &Message{
		Type:    channel,
		Payload: payload,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshaling broadcast message: %v", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		select {
		case client.send <- data:
		default:
			// Client buffer full, skip
		}
	}
}

// broadcastToChannel sends message to subscribed clients
func (h *Hub) broadcastToChannel(message *Message) {
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling message: %v", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	subscribers := h.subscriptions[message.Type]
	for client := range subscribers {
		select {
		case client.send <- data:
		default:
			// Client buffer full, skip
		}
	}
}

// ClientCount returns the number of connected clients
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ChannelSubscriberCount returns the number of subscribers for a channel
func (h *Hub) ChannelSubscriberCount(channel string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subscriptions[channel])
}
