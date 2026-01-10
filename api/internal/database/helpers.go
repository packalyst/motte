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

// Int64FromNull converts sql.NullInt64 to int64 with a default value
func Int64FromNull(ni sql.NullInt64, defaultVal int64) int64 {
	if ni.Valid {
		return ni.Int64
	}
	return defaultVal
}

// Float64FromNull converts sql.NullFloat64 to float64 with a default value
func Float64FromNull(nf sql.NullFloat64, defaultVal float64) float64 {
	if nf.Valid {
		return nf.Float64
	}
	return defaultVal
}
