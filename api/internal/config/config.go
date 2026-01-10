package config

import (
	"encoding/json"
	"os"
	"sync"
)

// EndpointConfig represents a single endpoint configuration
type EndpointConfig struct {
	Path        string   `json:"path"`
	Methods     []string `json:"methods"`
	Handler     string   `json:"handler"`
	Description string   `json:"description"`
}

// ServiceConfig represents a service configuration
type ServiceConfig struct {
	Prefix    string           `json:"prefix"`
	Enabled   bool             `json:"enabled"`
	Endpoints []EndpointConfig `json:"endpoints"`
}

// CORSConfig represents CORS middleware configuration
type CORSConfig struct {
	Enabled      bool     `json:"enabled"`
	AllowOrigins []string `json:"allowOrigins"`
	AllowMethods []string `json:"allowMethods"`
	AllowHeaders []string `json:"allowHeaders"`
}

// LoggingConfig represents logging middleware configuration
type LoggingConfig struct {
	Enabled bool   `json:"enabled"`
	Format  string `json:"format"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool `json:"enabled"`
	RequestsPerSecond int  `json:"requestsPerSecond"`
}

// MiddlewareConfig represents all middleware configurations
type MiddlewareConfig struct {
	CORS      CORSConfig      `json:"cors"`
	Logging   LoggingConfig   `json:"logging"`
	RateLimit RateLimitConfig `json:"rateLimit"`
}

// FirewallAppConfig holds firewall-specific configuration
type FirewallAppConfig struct {
	MaxAttempts          int `json:"maxAttempts"`
	JailCheckIntervalSec int `json:"jailCheckIntervalSec"`
	CleanupIntervalMin   int `json:"cleanupIntervalMin"`
	DNSLookupTimeoutSec  int `json:"dnsLookupTimeoutSec"`
}

// SessionAppConfig holds session-specific configuration
type SessionAppConfig struct {
	TimeoutHours int `json:"timeoutHours"`
}

// WebSocketAppConfig holds WebSocket-specific configuration
type WebSocketAppConfig struct {
	WriteWaitSec           int      `json:"writeWaitSec"`
	PongWaitSec            int      `json:"pongWaitSec"`
	MaxMessageSize         int64    `json:"maxMessageSize"`
	SendBufferSize         int      `json:"sendBufferSize"`
	ReadBufferSize         int      `json:"readBufferSize"`
	WriteBufferSize        int      `json:"writeBufferSize"`
	BroadcastBufferSize    int      `json:"broadcastBufferSize"`
	StatusCheckIntervalSec int      `json:"statusCheckIntervalSec"`
	Channels               []string `json:"channels"`
}

// AppConfig holds application-level configurations
type AppConfig struct {
	Firewall  FirewallAppConfig  `json:"firewall"`
	Session   SessionAppConfig   `json:"session"`
	WebSocket WebSocketAppConfig `json:"websocket"`
}

// Config represents the complete endpoints configuration
type Config struct {
	Version    string                   `json:"version"`
	App        AppConfig                `json:"app"`
	Services   map[string]ServiceConfig `json:"services"`
	Middleware MiddlewareConfig         `json:"middleware"`
}

var (
	config     *Config
	configOnce sync.Once
	configPath string
)

// Load loads the configuration from the specified path
func Load(path string) (*Config, error) {
	configPath = path

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	config = &cfg
	return config, nil
}

// Get returns the loaded configuration
func Get() *Config {
	return config
}

// GetService returns a specific service configuration
func GetService(name string) *ServiceConfig {
	if config == nil {
		return nil
	}
	if svc, ok := config.Services[name]; ok {
		return &svc
	}
	return nil
}

// IsServiceEnabled checks if a service is enabled
func IsServiceEnabled(name string) bool {
	svc := GetService(name)
	return svc != nil && svc.Enabled
}

// GetApp returns the application configuration
func GetApp() *AppConfig {
	if config == nil {
		return nil
	}
	return &config.App
}

// GetFirewallConfig returns firewall-specific config with defaults
func GetFirewallConfig() FirewallAppConfig {
	if config == nil {
		return FirewallAppConfig{
			MaxAttempts:          10000,
			JailCheckIntervalSec: 10,
			CleanupIntervalMin:   5,
			DNSLookupTimeoutSec:  2,
		}
	}
	cfg := config.App.Firewall
	// Apply defaults for zero values
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 10000
	}
	if cfg.JailCheckIntervalSec == 0 {
		cfg.JailCheckIntervalSec = 10
	}
	if cfg.CleanupIntervalMin == 0 {
		cfg.CleanupIntervalMin = 5
	}
	if cfg.DNSLookupTimeoutSec == 0 {
		cfg.DNSLookupTimeoutSec = 2
	}
	return cfg
}

// GetSessionConfig returns session-specific config with defaults
func GetSessionConfig() SessionAppConfig {
	if config == nil {
		return SessionAppConfig{TimeoutHours: 24}
	}
	cfg := config.App.Session
	if cfg.TimeoutHours == 0 {
		cfg.TimeoutHours = 24
	}
	return cfg
}

// GetWebSocketConfig returns WebSocket-specific config
func GetWebSocketConfig() WebSocketAppConfig {
	if config == nil {
		return WebSocketAppConfig{}
	}
	return config.App.WebSocket
}
