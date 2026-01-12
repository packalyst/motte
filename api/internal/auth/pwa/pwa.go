// Package pwa provides Progressive Web App functionality including
// push notifications, device location tracking, and user preferences.
package pwa

import (
	"errors"
	"log"
	"sync"

	"api/internal/auth"
	"api/internal/database"
	"api/internal/firewall"
	"api/internal/helper"
	"api/internal/settings"
	"api/internal/ws"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// Settings keys for VAPID
const (
	settingVAPIDPublic  = "vapid_public_key"
	settingVAPIDPrivate = "vapid_private_key"
	settingVAPIDSubject = "vapid_subject"
)

// PushTTL is how long (seconds) push services retry delivery if device is offline
const PushTTL = 86400 // 24 hours

// Service handles all PWA-related operations
type Service struct {
	db         *database.DB
	vapidKeys  *VAPIDKeys
	subject    string
	mu         sync.RWMutex
}

var (
	instance *Service
	once     sync.Once
	initErr  error // Persists initialization error across calls

	ErrNotInitialized       = errors.New("pwa service not initialized")
	ErrInvalidSubscription  = errors.New("invalid push subscription")
	ErrSubscriptionExists   = errors.New("subscription already exists")
	ErrSubscriptionNotFound = errors.New("subscription not found")
)

// Init initializes the PWA service (call once at startup)
func Init() (*Service, error) {
	once.Do(func() {
		db, err := database.GetDB()
		if err != nil {
			initErr = err
			return
		}

		svc := &Service{db: db}

		// Load or generate VAPID keys
		if err := svc.initVAPIDKeys(); err != nil {
			initErr = err
			return
		}

		instance = svc

		// Register login notification callback with auth package
		auth.SetLoginNotifyCallback(func(userID int64, ip, device, userAgent string) {
			svc.NotifyNewLogin(userID, ip, device, userAgent)
		})

		// Register node status change callback for push notifications
		ws.SetNodeStatusChangeCallback(func(nodeName string, online bool) {
			if online {
				svc.NotifyNodeOnline(nodeName)
			} else {
				svc.NotifyNodeOffline(nodeName)
			}
		})

		// Register firewall block callback for push notifications
		firewall.SetBlockNotifyCallback(func(ip, reason string) {
			svc.NotifyFirewallAlert(ip, reason)
		})
	})

	return instance, initErr
}

// Get returns the singleton PWA service instance
func Get() *Service {
	return instance
}

// getVAPIDSubject returns the VAPID subject built from SSL_DOMAIN
// Note: webpush-go auto-prepends "mailto:" so we only pass the email
func getVAPIDSubject() string {
	domain := helper.GetEnv("SSL_DOMAIN")
	return "push@" + domain
}

// initVAPIDKeys loads existing VAPID keys from settings or generates new ones
func (s *Service) initVAPIDKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get VAPID subject (from env, settings, or domain)
	s.subject = getVAPIDSubject()

	// Try to load existing keys
	publicKey, _ := settings.GetSetting(settingVAPIDPublic)
	privateKey, _ := settings.GetSettingEncrypted(settingVAPIDPrivate)

	// If we have both keys, use them
	if publicKey != "" && privateKey != "" {
		s.vapidKeys = &VAPIDKeys{
			PublicKey:  publicKey,
			PrivateKey: privateKey,
		}
		// Update subject in settings if it changed
		settings.SetSetting(settingVAPIDSubject, s.subject)
		return nil
	}

	// Keys don't exist yet - generate new ones

	// Generate new VAPID keys using webpush-go's generator
	log.Printf("Generating new VAPID keys...")

	var err error
	privateKey, publicKey, err = webpush.GenerateVAPIDKeys()
	if err != nil {
		return err
	}

	// Encrypt private key before storage
	encryptedPrivate, err := helper.Encrypt(privateKey)
	if err != nil {
		return err
	}

	// Store all keys in a transaction to prevent partial state
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // No-op if committed

	stmt := `INSERT OR REPLACE INTO settings (key, value, encrypted, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`
	if _, err := tx.Exec(stmt, settingVAPIDPublic, publicKey, false); err != nil {
		return err
	}
	if _, err := tx.Exec(stmt, settingVAPIDPrivate, encryptedPrivate, true); err != nil {
		return err
	}
	if _, err := tx.Exec(stmt, settingVAPIDSubject, s.subject, false); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.vapidKeys = &VAPIDKeys{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	log.Printf("VAPID keys generated and stored")
	return nil
}

// GetVAPIDPublicKey returns the public VAPID key for client subscription
func (s *Service) GetVAPIDPublicKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.vapidKeys == nil {
		return ""
	}
	return s.vapidKeys.PublicKey
}

// sendPush sends a push notification to a subscription
func (s *Service) sendPush(sub *PushSubscription, payload []byte) error {
	s.mu.RLock()
	if s.vapidKeys == nil {
		s.mu.RUnlock()
		return ErrNotInitialized
	}
	vapidPublic := s.vapidKeys.PublicKey
	vapidPrivate := s.vapidKeys.PrivateKey
	subject := s.subject
	s.mu.RUnlock()

	subscription := &webpush.Subscription{
		Endpoint: sub.Endpoint,
		Keys: webpush.Keys{
			P256dh: sub.KeyP256DH,
			Auth:   sub.KeyAuth,
		},
	}

	resp, err := webpush.SendNotification(payload, subscription, &webpush.Options{
		Subscriber:      subject,
		VAPIDPublicKey:  vapidPublic,
		VAPIDPrivateKey: vapidPrivate,
		TTL:             PushTTL,
		Urgency:         webpush.UrgencyNormal,
	})

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Update last_used_at timestamp
	if _, err := s.db.Exec(`UPDATE users_push_subscriptions SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, sub.ID); err != nil {
		return err
	}

	// Handle expired/invalid subscriptions (410 Gone or 404 Not Found)
	if resp.StatusCode == 410 || resp.StatusCode == 404 {
		s.DeleteSubscription(sub.ID, sub.UserID)
		return errors.New("subscription expired or invalid")
	}

	// Check for other errors (201 is success for web push)
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return errors.New("push service returned error")
	}

	return nil
}
