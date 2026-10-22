package pwa

import ()

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
