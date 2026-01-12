package pwa

import "time"

// PushSubscription represents a Web Push API subscription
type PushSubscription struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"userId"`
	DeviceName string     `json:"deviceName"`
	Endpoint   string     `json:"endpoint"`
	KeyP256DH  string     `json:"keyP256dh"`
	KeyAuth    string     `json:"keyAuth"`
	UserAgent  string     `json:"userAgent,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	LoadError  string     `json:"loadError,omitempty"` // Set if row failed to load properly
}

// SubscribeRequest represents a push subscription request from client
type SubscribeRequest struct {
	DeviceName   string `json:"deviceName"`
	Endpoint     string `json:"endpoint"`
	KeyP256DH    string `json:"keyP256dh"`
	KeyAuth      string `json:"keyAuth"`
	ExpirationTime *int64 `json:"expirationTime,omitempty"`
}

// NotificationPreferences represents user's notification settings (key-value)
type NotificationPreferences map[string]bool

// DeviceLocation represents a GPS location record
type DeviceLocation struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"userId"`
	DeviceName string    `json:"deviceName"`
	Latitude   float64   `json:"latitude"`
	Longitude  float64   `json:"longitude"`
	Accuracy   *float64  `json:"accuracy,omitempty"`
	Altitude   *float64  `json:"altitude,omitempty"`
	Heading    *float64  `json:"heading,omitempty"`
	Speed      *float64  `json:"speed,omitempty"`
	RecordedAt time.Time `json:"recordedAt"`
}

// LocationRequest represents a location submission from client
type LocationRequest struct {
	DeviceName string   `json:"deviceName"`
	Latitude   float64  `json:"latitude"`
	Longitude  float64  `json:"longitude"`
	Accuracy   *float64 `json:"accuracy,omitempty"`
	Altitude   *float64 `json:"altitude,omitempty"`
	Heading    *float64 `json:"heading,omitempty"`
	Speed      *float64 `json:"speed,omitempty"`
}

// Notification represents a push notification to send
type Notification struct {
	Title   string            `json:"title"`
	Body    string            `json:"body"`
	Icon    string            `json:"icon,omitempty"`
	Badge   string            `json:"badge,omitempty"`
	Tag     string            `json:"tag,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
	Actions []NotificationAction `json:"actions,omitempty"`
}

// NotificationAction represents an action button on a notification
type NotificationAction struct {
	Action string `json:"action"`
	Title  string `json:"title"`
	Icon   string `json:"icon,omitempty"`
}

// NotificationType defines the type of notification for filtering
type NotificationType string

const (
	NotifyNodeOffline    NotificationType = "node_offline"
	NotifyNodeOnline     NotificationType = "node_online"
	NotifyFirewallAlert  NotificationType = "firewall_alert"
	NotifyLoginNewDevice NotificationType = "login_new_device"
	NotifySystemAlert    NotificationType = "system_alert"
)

// DefaultNotificationIcon is the icon used for all push notifications
const DefaultNotificationIcon = "/icon-192.png"

// PreferenceDefaults defines default values for each notification type
// To add a new preference: add const above + add default here + add UI toggle
var PreferenceDefaults = map[NotificationType]bool{
	NotifyNodeOffline:    true,  // ON - important to know when nodes go down
	NotifyNodeOnline:     false, // OFF - can be noisy
	NotifyFirewallAlert:  true,  // ON - security alerts
	NotifyLoginNewDevice: true,  // ON - security alerts
	NotifySystemAlert:    true,  // ON - important system notifications
}

// AllNotificationTypes returns all available notification types (for UI)
func AllNotificationTypes() []NotificationType {
	return []NotificationType{
		NotifyNodeOffline,
		NotifyNodeOnline,
		NotifyFirewallAlert,
		NotifyLoginNewDevice,
		NotifySystemAlert,
	}
}

// VAPIDKeys holds the VAPID key pair for Web Push
type VAPIDKeys struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"-"` // Never expose private key in JSON
}
