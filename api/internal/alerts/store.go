package alerts

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
)

// Per-user rule storage. Each rule is owned by a user (user_id) — delivery (channels) lives in the
// notifications (pwa) package, shared with every other notification type.

func (s *Service) ensureTables() {
	s.cfgOnce.Do(func() {
		s.db.Exec(`CREATE TABLE IF NOT EXISTS alert_rules (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id     INTEGER NOT NULL,
			name        TEXT NOT NULL DEFAULT '',
			metric      TEXT NOT NULL,
			targets     TEXT NOT NULL DEFAULT '',
			threshold   REAL NOT NULL,
			for_min     INTEGER NOT NULL DEFAULT 0,
			enabled     INTEGER NOT NULL DEFAULT 1,
			created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
		s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id)`)
		// If an older build created alert_rules without the targets column, add it.
		s.db.Exec(`ALTER TABLE alert_rules ADD COLUMN targets TEXT NOT NULL DEFAULT ''`)
	})
}

// listRules returns one user's rules. When userID == 0 it returns every enabled rule across all
// users — used by the evaluator.
func (s *Service) listRules(userID int64) ([]Rule, error) {
	s.ensureTables()
	var (
		rows *sql.Rows
		err  error
	)
	if userID == 0 {
		rows, err = s.db.Query(`SELECT id, user_id, name, metric, targets, threshold, for_min, enabled
			FROM alert_rules WHERE enabled = 1`)
	} else {
		rows, err = s.db.Query(`SELECT id, user_id, name, metric, targets, threshold, for_min, enabled
			FROM alert_rules WHERE user_id = ? ORDER BY id`, userID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var targets string
		var enabled int
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &r.Metric, &targets, &r.Threshold, &r.ForMin, &enabled); err != nil {
			return nil, err
		}
		r.Targets = parseTargets(targets)
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) createRule(userID int64, r Rule) (Rule, error) {
	s.ensureTables()
	res, err := s.db.Exec(`INSERT INTO alert_rules (user_id, name, metric, targets, threshold, for_min, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, r.Name, r.Metric, marshalTargets(r.Targets), r.Threshold, r.ForMin, boolToInt(r.Enabled))
	if err != nil {
		return Rule{}, err
	}
	id, _ := res.LastInsertId()
	r.ID = id
	r.UserID = userID
	return r, nil
}

// updateRule updates a rule only if it belongs to userID (ownership enforced in the WHERE).
func (s *Service) updateRule(userID, id int64, r Rule) error {
	s.ensureTables()
	res, err := s.db.Exec(`UPDATE alert_rules
		SET name = ?, metric = ?, targets = ?, threshold = ?, for_min = ?, enabled = ?
		WHERE id = ? AND user_id = ?`,
		r.Name, r.Metric, marshalTargets(r.Targets), r.Threshold, r.ForMin, boolToInt(r.Enabled), id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *Service) deleteRule(userID, id int64) error {
	s.ensureTables()
	res, err := s.db.Exec(`DELETE FROM alert_rules WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	// Drop any live breach state for this rule's targets.
	s.mu.Lock()
	prefix := strconv.FormatInt(id, 10) + ":"
	for k := range s.st {
		if strings.HasPrefix(k, prefix) {
			delete(s.st, k)
		}
	}
	s.mu.Unlock()
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var errNotFound = errors.New("rule not found")
