package alerts

import (
	"database/sql"
	"errors"
	"strings"

	"api/internal/helper"
)

// Per-user alerting storage. Rules and delivery channels are owned by a user (user_id) — each
// admin manages their own, delivered to their own devices/webhook/email — rather than one global
// policy. This mirrors the existing per-user notification preferences in the pwa package.

func (s *Service) ensureTables() {
	s.cfgOnce.Do(func() {
		s.db.Exec(`CREATE TABLE IF NOT EXISTS alert_rules (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id     INTEGER NOT NULL,
			name        TEXT NOT NULL DEFAULT '',
			metric      TEXT NOT NULL,
			scope       TEXT NOT NULL DEFAULT 'host',
			machine_id  TEXT NOT NULL DEFAULT '',
			threshold   REAL NOT NULL,
			for_min     INTEGER NOT NULL DEFAULT 0,
			enabled     INTEGER NOT NULL DEFAULT 1,
			created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
		s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id)`)
		s.db.Exec(`CREATE TABLE IF NOT EXISTS alert_channels (
			user_id         INTEGER PRIMARY KEY,
			webhook_url_enc TEXT NOT NULL DEFAULT '',
			webhook_enabled INTEGER NOT NULL DEFAULT 0,
			email           TEXT NOT NULL DEFAULT '',
			email_enabled   INTEGER NOT NULL DEFAULT 0,
			push_enabled    INTEGER NOT NULL DEFAULT 1
		)`)
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
		rows, err = s.db.Query(`SELECT id, user_id, name, metric, scope, machine_id, threshold, for_min, enabled
			FROM alert_rules WHERE enabled = 1`)
	} else {
		rows, err = s.db.Query(`SELECT id, user_id, name, metric, scope, machine_id, threshold, for_min, enabled
			FROM alert_rules WHERE user_id = ? ORDER BY id`, userID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var enabled int
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &r.Metric, &r.Scope, &r.MachineID, &r.Threshold, &r.ForMin, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) createRule(userID int64, r Rule) (Rule, error) {
	s.ensureTables()
	res, err := s.db.Exec(`INSERT INTO alert_rules (user_id, name, metric, scope, machine_id, threshold, for_min, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, r.Name, r.Metric, r.Scope, r.MachineID, r.Threshold, r.ForMin, boolToInt(r.Enabled))
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
		SET name = ?, metric = ?, scope = ?, machine_id = ?, threshold = ?, for_min = ?, enabled = ?
		WHERE id = ? AND user_id = ?`,
		r.Name, r.Metric, r.Scope, r.MachineID, r.Threshold, r.ForMin, boolToInt(r.Enabled), id, userID)
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
	// Drop any live breach state for this rule.
	s.mu.Lock()
	for k := range s.st {
		if strings.HasPrefix(k, ruleKey(id)+":") || k == ruleKey(id) {
			delete(s.st, k)
		}
	}
	s.mu.Unlock()
	return nil
}

// getChannels returns a user's delivery settings (webhook URL decrypted for internal use).
func (s *Service) getChannels(userID int64) (Channels, error) {
	s.ensureTables()
	var (
		enc                                       string
		webhookEnabled, emailEnabled, pushEnabled int
		email                                     string
	)
	err := s.db.QueryRow(`SELECT webhook_url_enc, webhook_enabled, email, email_enabled, push_enabled
		FROM alert_channels WHERE user_id = ?`, userID).Scan(&enc, &webhookEnabled, &email, &emailEnabled, &pushEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Channels{PushEnabled: true}, nil // sensible default: push on, nothing else set
	}
	if err != nil {
		return Channels{}, err
	}
	url := ""
	if enc != "" {
		if dec, derr := helper.Decrypt(enc); derr == nil {
			url = dec
		}
	}
	return Channels{
		WebhookURL:     url,
		WebhookEnabled: webhookEnabled == 1,
		Email:          email,
		EmailEnabled:   emailEnabled == 1,
		PushEnabled:    pushEnabled == 1,
	}, nil
}

func (s *Service) saveChannels(userID int64, c Channels) error {
	s.ensureTables()
	enc := ""
	if c.WebhookURL != "" {
		e, err := helper.Encrypt(c.WebhookURL)
		if err != nil {
			return err
		}
		enc = e
	}
	_, err := s.db.Exec(`INSERT INTO alert_channels (user_id, webhook_url_enc, webhook_enabled, email, email_enabled, push_enabled)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			webhook_url_enc = excluded.webhook_url_enc,
			webhook_enabled = excluded.webhook_enabled,
			email = excluded.email,
			email_enabled = excluded.email_enabled,
			push_enabled = excluded.push_enabled`,
		userID, enc, boolToInt(c.WebhookEnabled), c.Email, boolToInt(c.EmailEnabled), boolToInt(c.PushEnabled))
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var errNotFound = errors.New("rule not found")
