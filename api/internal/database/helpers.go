package database

import (
	"database/sql"
	"strings"
	"time"
)

// EscapeLikePattern escapes SQL LIKE special characters (%, _, \)
func EscapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// TimePointerFromNull converts sql.NullTime to *time.Time
// Returns nil if the value is not valid
func TimePointerFromNull(nt sql.NullTime) *time.Time {
	if nt.Valid {
		return &nt.Time
	}
	return nil
}

// TimeFromNull converts sql.NullTime to time.Time with a default value
func TimeFromNull(nt sql.NullTime, defaultVal time.Time) time.Time {
	if nt.Valid {
		return nt.Time
	}
	return defaultVal
}

// StringFromNull converts sql.NullString to string with a default value
func StringFromNull(ns sql.NullString, defaultVal string) string {
	if ns.Valid {
		return ns.String
	}
	return defaultVal
}

// StringFromNullNotEmpty converts sql.NullString to string, treating empty strings as default
func StringFromNullNotEmpty(ns sql.NullString, defaultVal string) string {
	if ns.Valid && ns.String != "" {
		return ns.String
	}
	return defaultVal
}

// BoolFromNull converts sql.NullBool to bool with a default value
func BoolFromNull(nb sql.NullBool, defaultVal bool) bool {
	if nb.Valid {
		return nb.Bool
	}
	return defaultVal
}

// InTx runs fn in a transaction: committed when fn succeeds, rolled back when it fails.
func (d *DB) InTx(fn func(tx *sql.Tx) error) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
