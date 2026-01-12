package pwa

import (
	"database/sql"
	"strings"
	"time"
)

// MaxLocationResults is the maximum number of location records returned per query
const MaxLocationResults = 100

// StoreLocation saves a device location record
func (s *Service) StoreLocation(userID int64, req *LocationRequest) (*DeviceLocation, error) {
	// Sanitize device name (limit to 64 chars)
	deviceName := strings.TrimSpace(req.DeviceName)
	if len(deviceName) > 64 {
		deviceName = deviceName[:64]
	}
	if deviceName == "" {
		deviceName = "Unknown Device"
	}

	result, err := s.db.Exec(`
		INSERT INTO users_device_locations (user_id, device_name, latitude, longitude, accuracy, altitude, heading, speed, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, userID, deviceName, req.Latitude, req.Longitude, req.Accuracy, req.Altitude, req.Heading, req.Speed)

	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	return &DeviceLocation{
		ID:         id,
		UserID:     userID,
		DeviceName: deviceName,
		Latitude:   req.Latitude,
		Longitude:  req.Longitude,
		Accuracy:   req.Accuracy,
		Altitude:   req.Altitude,
		Heading:    req.Heading,
		Speed:      req.Speed,
		RecordedAt: time.Now(),
	}, nil
}

// GetUserLocations returns recent locations for a user
// Optimized: uses composite index (user_id, recorded_at DESC), limits results
func (s *Service) GetUserLocations(userID int64, limit int) ([]DeviceLocation, error) {
	if limit <= 0 || limit > MaxLocationResults {
		limit = MaxLocationResults
	}

	rows, err := s.db.Query(`
		SELECT id, user_id, device_name, latitude, longitude, accuracy, altitude, heading, speed, recorded_at
		FROM users_device_locations
		WHERE user_id = ?
		ORDER BY recorded_at DESC
		LIMIT ?
	`, userID, limit)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanLocations(rows)
}

// GetLatestLocationPerDevice returns the most recent location for each device
// Optimized: uses window function equivalent with subquery
func (s *Service) GetLatestLocationPerDevice(userID int64) ([]DeviceLocation, error) {
	rows, err := s.db.Query(`
		SELECT l.id, l.user_id, l.device_name, l.latitude, l.longitude, l.accuracy, l.altitude, l.heading, l.speed, l.recorded_at
		FROM users_device_locations l
		INNER JOIN (
			SELECT device_name, MAX(recorded_at) as max_time
			FROM users_device_locations
			WHERE user_id = ?
			GROUP BY device_name
		) latest ON l.device_name = latest.device_name AND l.recorded_at = latest.max_time
		WHERE l.user_id = ?
		ORDER BY l.recorded_at DESC
	`, userID, userID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanLocations(rows)
}

// GetLocationsByTimeRange returns locations within a time range
// Optimized: indexed query with time bounds
func (s *Service) GetLocationsByTimeRange(userID int64, start, end time.Time, limit int) ([]DeviceLocation, error) {
	if limit <= 0 || limit > MaxLocationResults {
		limit = MaxLocationResults
	}

	rows, err := s.db.Query(`
		SELECT id, user_id, device_name, latitude, longitude, accuracy, altitude, heading, speed, recorded_at
		FROM users_device_locations
		WHERE user_id = ? AND recorded_at BETWEEN ? AND ?
		ORDER BY recorded_at DESC
		LIMIT ?
	`, userID, start, end, limit)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanLocations(rows)
}

// DeleteLocation removes a specific location record
func (s *Service) DeleteLocation(userID, locationID int64) error {
	result, err := s.db.Exec(`
		DELETE FROM users_device_locations
		WHERE id = ? AND user_id = ?
	`, locationID, userID)

	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// DeleteOldLocations removes locations older than specified duration
// Useful for cleanup/retention policy
func (s *Service) DeleteOldLocations(userID int64, olderThan time.Time) (int64, error) {
	result, err := s.db.Exec(`
		DELETE FROM users_device_locations
		WHERE user_id = ? AND recorded_at < ?
	`, userID, olderThan)

	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// DeleteAllLocations removes all locations for a user
func (s *Service) DeleteAllLocations(userID int64) error {
	_, err := s.db.Exec(`
		DELETE FROM users_device_locations
		WHERE user_id = ?
	`, userID)
	return err
}

// GetLocationCount returns total location records for a user
func (s *Service) GetLocationCount(userID int64) (int64, error) {
	var count int64
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM users_device_locations WHERE user_id = ?
	`, userID).Scan(&count)
	return count, err
}

// scanLocations is a helper to scan location rows
func scanLocations(rows *sql.Rows) ([]DeviceLocation, error) {
	var locations []DeviceLocation

	for rows.Next() {
		var loc DeviceLocation
		var accuracy, altitude, heading, speed sql.NullFloat64

		if err := rows.Scan(
			&loc.ID, &loc.UserID, &loc.DeviceName,
			&loc.Latitude, &loc.Longitude,
			&accuracy, &altitude, &heading, &speed,
			&loc.RecordedAt,
		); err != nil {
			continue
		}

		if accuracy.Valid {
			loc.Accuracy = &accuracy.Float64
		}
		if altitude.Valid {
			loc.Altitude = &altitude.Float64
		}
		if heading.Valid {
			loc.Heading = &heading.Float64
		}
		if speed.Valid {
			loc.Speed = &speed.Float64
		}

		locations = append(locations, loc)
	}

	return locations, nil
}
