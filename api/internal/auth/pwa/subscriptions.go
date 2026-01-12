package pwa

import (
	"database/sql"
	"strings"
	"time"

	"api/internal/helper"
)

// Subscribe registers a new push subscription for a user
// Uses INSERT OR REPLACE to handle re-subscription from same endpoint
func (s *Service) Subscribe(userID int64, req *SubscribeRequest, userAgent string) (*PushSubscription, error) {
	if req.Endpoint == "" || req.KeyP256DH == "" || req.KeyAuth == "" {
		return nil, ErrInvalidSubscription
	}

	// Validate endpoint is HTTPS URL (all push services use HTTPS)
	if !strings.HasPrefix(req.Endpoint, "https://") {
		return nil, ErrInvalidSubscription
	}

	// Validate input lengths to prevent abuse
	if len(req.Endpoint) > 2048 || len(req.KeyP256DH) > 512 || len(req.KeyAuth) > 512 {
		return nil, ErrInvalidSubscription
	}

	// Validate endpoint is from a known push service (prevents SSRF)
	if !isValidPushEndpoint(req.Endpoint) {
		return nil, ErrInvalidSubscription
	}

	// Normalize device name (limit to 64 chars)
	deviceName := strings.TrimSpace(req.DeviceName)
	if len(deviceName) > 64 {
		deviceName = deviceName[:64]
	}
	if deviceName == "" {
		deviceName = helper.ParseUserAgent(userAgent)
	}

	// Encrypt sensitive keys before storage
	encP256DH, err := helper.Encrypt(req.KeyP256DH)
	if err != nil {
		return nil, err
	}
	encAuth, err := helper.Encrypt(req.KeyAuth)
	if err != nil {
		return nil, err
	}

	// Use INSERT OR REPLACE to handle re-subscriptions from same endpoint
	// This updates the subscription if endpoint already exists
	result, err := s.db.Exec(`
		INSERT INTO users_push_subscriptions (user_id, device_name, endpoint, key_p256dh, key_auth, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(endpoint) DO UPDATE SET
			user_id = excluded.user_id,
			device_name = excluded.device_name,
			key_p256dh = excluded.key_p256dh,
			key_auth = excluded.key_auth,
			user_agent = excluded.user_agent
	`, userID, deviceName, req.Endpoint, encP256DH, encAuth, userAgent)

	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	return &PushSubscription{
		ID:         id,
		UserID:     userID,
		DeviceName: deviceName,
		Endpoint:   req.Endpoint,
		KeyP256DH:  req.KeyP256DH,
		KeyAuth:    req.KeyAuth,
		UserAgent:  userAgent,
		CreatedAt:  time.Now(),
	}, nil
}

// Unsubscribe removes a push subscription by endpoint
func (s *Service) Unsubscribe(userID int64, endpoint string) error {
	result, err := s.db.Exec(`
		DELETE FROM users_push_subscriptions
		WHERE user_id = ? AND endpoint = ?
	`, userID, endpoint)

	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrSubscriptionNotFound
	}

	return nil
}

// DeleteSubscription removes a subscription by ID (internal use)
func (s *Service) DeleteSubscription(id, userID int64) error {
	_, err := s.db.Exec(`
		DELETE FROM users_push_subscriptions
		WHERE id = ? AND user_id = ?
	`, id, userID)
	return err
}

// scanSubscription scans a row into PushSubscription and decrypts keys
// If decryption fails, returns subscription with LoadError set (still usable for display)
func scanSubscription(rows *sql.Rows) (*PushSubscription, error) {
	var sub PushSubscription
	var lastUsed sql.NullTime
	var encP256DH, encAuth string

	if err := rows.Scan(
		&sub.ID, &sub.UserID, &sub.DeviceName, &sub.Endpoint,
		&encP256DH, &encAuth, &sub.UserAgent,
		&sub.CreatedAt, &lastUsed,
	); err != nil {
		// Can't even read basic fields - skip this row
		return nil, err
	}

	if lastUsed.Valid {
		sub.LastUsedAt = &lastUsed.Time
	}

	// Decrypt keys - if fails, mark subscription as broken but still return it
	p256dh, err := helper.Decrypt(encP256DH)
	if err != nil {
		sub.LoadError = "decryption failed"
		return &sub, nil
	}
	auth, err := helper.Decrypt(encAuth)
	if err != nil {
		sub.LoadError = "decryption failed"
		return &sub, nil
	}

	sub.KeyP256DH = p256dh
	sub.KeyAuth = auth

	return &sub, nil
}

// GetUserSubscriptions returns all push subscriptions for a user
// Optimized: single query, indexed by user_id
func (s *Service) GetUserSubscriptions(userID int64) ([]PushSubscription, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, device_name, endpoint, key_p256dh, key_auth, user_agent, created_at, last_used_at
		FROM users_push_subscriptions
		WHERE user_id = ?
		ORDER BY created_at DESC
	`, userID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []PushSubscription
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			continue // Skip malformed entries
		}
		subs = append(subs, *sub)
	}

	return subs, nil
}

// GetUserSubscriptionsExcluding returns subscriptions for a user, excluding those matching the user agent
// Used for login notifications - don't notify the device that just logged in
func (s *Service) GetUserSubscriptionsExcluding(userID int64, excludeUserAgent string) ([]PushSubscription, error) {
	// Get default for login notifications
	defaultEnabled := 1
	if defVal, ok := PreferenceDefaults[NotifyLoginNewDevice]; ok && !defVal {
		defaultEnabled = 0
	}

	// Query with preference check and user agent exclusion
	rows, err := s.db.Query(`
		SELECT s.id, s.user_id, s.device_name, s.endpoint, s.key_p256dh, s.key_auth, s.user_agent, s.created_at, s.last_used_at
		FROM users_push_subscriptions s
		LEFT JOIN users_notification_preferences p
			ON s.user_id = p.user_id AND p.pref_key = ?
		WHERE s.user_id = ?
			AND s.user_agent != ?
			AND COALESCE(p.enabled, ?) = 1
		ORDER BY s.created_at DESC
	`, string(NotifyLoginNewDevice), userID, excludeUserAgent, defaultEnabled)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []PushSubscription
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			continue
		}
		subs = append(subs, *sub)
	}

	return subs, nil
}

// GetAllSubscriptionsForNotificationType returns all subscriptions that should receive a notification type
// Uses key-value preferences table with defaults from PreferenceDefaults
func (s *Service) GetAllSubscriptionsForNotificationType(notifType NotificationType) ([]PushSubscription, error) {
	// Get default value for this notification type
	defaultEnabled := 1
	if defVal, ok := PreferenceDefaults[notifType]; ok && !defVal {
		defaultEnabled = 0
	}

	// Query: get subscriptions where user has this preference enabled (or default if no row)
	// LEFT JOIN with specific pref_key, use COALESCE for default
	query := `
		SELECT s.id, s.user_id, s.device_name, s.endpoint, s.key_p256dh, s.key_auth, s.user_agent, s.created_at, s.last_used_at
		FROM users_push_subscriptions s
		LEFT JOIN users_notification_preferences p
			ON s.user_id = p.user_id AND p.pref_key = ?
		WHERE COALESCE(p.enabled, ?) = 1
	`

	rows, err := s.db.Query(query, string(notifType), defaultEnabled)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []PushSubscription
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			continue
		}
		subs = append(subs, *sub)
	}

	return subs, nil
}

// GetSubscriptionsByUserIDs returns subscriptions for specific users
// Optimized: uses IN clause for batch lookup
func (s *Service) GetSubscriptionsByUserIDs(userIDs []int64) ([]PushSubscription, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}

	// Build placeholders for IN clause
	placeholders := make([]string, len(userIDs))
	args := make([]interface{}, len(userIDs))
	for i, id := range userIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := `
		SELECT id, user_id, device_name, endpoint, key_p256dh, key_auth, user_agent, created_at, last_used_at
		FROM users_push_subscriptions
		WHERE user_id IN (` + strings.Join(placeholders, ",") + `)
	`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []PushSubscription
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			continue
		}
		subs = append(subs, *sub)
	}

	return subs, nil
}


// validPushDomains contains allowed push service domains
var validPushDomains = []string{
	"fcm.googleapis.com",           // Google/Android/Chrome
	"web.push.apple.com",           // Apple/Safari/iOS
	"updates.push.services.mozilla.com", // Firefox
	".notify.windows.com",          // Edge/Windows (wildcard suffix)
}

// isValidPushEndpoint checks if the endpoint is from a known push service
func isValidPushEndpoint(endpoint string) bool {
	// Remove https:// prefix for domain check
	domain := strings.TrimPrefix(endpoint, "https://")

	// Extract just the host part (before first /)
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}

	// Remove port if present
	if idx := strings.Index(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}

	for _, valid := range validPushDomains {
		if strings.HasPrefix(valid, ".") {
			// Wildcard suffix match (e.g., ".notify.windows.com")
			if strings.HasSuffix(domain, valid) {
				return true
			}
		} else {
			// Exact match
			if domain == valid {
				return true
			}
		}
	}

	return false
}
