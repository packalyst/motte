package pwa

import (
	"database/sql"
)

// GetPreferences returns all notification preferences for a user
// Returns defaults merged with user overrides
func (s *Service) GetPreferences(userID int64) (NotificationPreferences, error) {
	// Start with defaults
	prefs := make(NotificationPreferences)
	for key, defaultVal := range PreferenceDefaults {
		prefs[string(key)] = defaultVal
	}

	// Override with user's saved preferences
	rows, err := s.db.Query(`
		SELECT pref_key, enabled
		FROM users_notification_preferences
		WHERE user_id = ?
	`, userID)
	if err != nil {
		return prefs, err // Return defaults on error
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var enabled bool
		if err := rows.Scan(&key, &enabled); err != nil {
			continue
		}
		prefs[key] = enabled
	}

	return prefs, nil
}

// UpdatePreferences saves all preferences for a user (replaces existing)
func (s *Service) UpdatePreferences(userID int64, prefs NotificationPreferences) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete existing preferences
	_, err = tx.Exec(`DELETE FROM users_notification_preferences WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}

	// Insert new preferences (only save non-default values to save space, or save all - your choice)
	stmt, err := tx.Prepare(`
		INSERT INTO users_notification_preferences (user_id, pref_key, enabled)
		VALUES (?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for key, enabled := range prefs {
		_, err = stmt.Exec(userID, key, enabled)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// SetPreference updates a single preference
func (s *Service) SetPreference(userID int64, prefKey NotificationType, enabled bool) error {
	_, err := s.db.Exec(`
		INSERT INTO users_notification_preferences (user_id, pref_key, enabled, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, pref_key) DO UPDATE SET
			enabled = excluded.enabled,
			updated_at = CURRENT_TIMESTAMP
	`, userID, string(prefKey), enabled)
	return err
}

// IsNotificationEnabled checks if a user has a specific notification type enabled
func (s *Service) IsNotificationEnabled(userID int64, notifType NotificationType) bool {
	var enabled bool
	err := s.db.QueryRow(`
		SELECT enabled
		FROM users_notification_preferences
		WHERE user_id = ? AND pref_key = ?
	`, userID, string(notifType)).Scan(&enabled)

	if err == sql.ErrNoRows {
		// No row = use default
		if defaultVal, ok := PreferenceDefaults[notifType]; ok {
			return defaultVal
		}
		return true // Ultimate fallback
	}

	if err != nil {
		return true // On error, default to enabled
	}

	return enabled
}
