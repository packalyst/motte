package pwa

import (
	"database/sql"
	"errors"
	"sync"

	"api/internal/helper"
)

// Channels is a user's NON-push delivery configuration, shared by EVERY notification type
// (node/firewall/login/system/resource). Push is governed by whether the user has subscribed a
// device (the existing push-enable control), so it is not duplicated here. "What" (which events)
// is the per-event preferences; "how" is push (subscriptions) + these channels.
type Channels struct {
	WebhookURL     string `json:"webhookUrl"` // sensitive → write-only to the UI
	WebhookEnabled bool   `json:"webhookEnabled"`
	Email          string `json:"email"`
	EmailEnabled   bool   `json:"emailEnabled"`
}

const ChannelRedacted = "__stored__"

var channelsTableOnce sync.Once

func (s *Service) ensureChannelsTable() {
	channelsTableOnce.Do(func() {
		s.db.Exec(`CREATE TABLE IF NOT EXISTS notification_channels (
			user_id         INTEGER PRIMARY KEY,
			webhook_url_enc TEXT NOT NULL DEFAULT '',
			webhook_enabled INTEGER NOT NULL DEFAULT 0,
			email           TEXT NOT NULL DEFAULT '',
			email_enabled   INTEGER NOT NULL DEFAULT 0
		)`)
	})
}

// GetChannels returns a user's delivery settings (webhook URL decrypted for internal use).
func (s *Service) GetChannels(userID int64) (Channels, error) {
	s.ensureChannelsTable()
	var (
		enc                          string
		email                        string
		webhookEnabled, emailEnabled int
	)
	err := s.db.QueryRow(`SELECT webhook_url_enc, webhook_enabled, email, email_enabled
		FROM notification_channels WHERE user_id = ?`, userID).
		Scan(&enc, &webhookEnabled, &email, &emailEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Channels{}, nil
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
	}, nil
}

func (s *Service) SaveChannels(userID int64, c Channels) error {
	s.ensureChannelsTable()
	enc := ""
	if c.WebhookURL != "" {
		e, err := helper.Encrypt(c.WebhookURL)
		if err != nil {
			return err
		}
		enc = e
	}
	_, err := s.db.Exec(`INSERT INTO notification_channels (user_id, webhook_url_enc, webhook_enabled, email, email_enabled)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			webhook_url_enc = excluded.webhook_url_enc,
			webhook_enabled = excluded.webhook_enabled,
			email = excluded.email,
			email_enabled = excluded.email_enabled`,
		userID, enc, b2i(c.WebhookEnabled), c.Email, b2i(c.EmailEnabled))
	return err
}

// Masked returns the channels with the webhook URL redacted (write-only to the UI).
func (c Channels) Masked() Channels {
	out := c
	if c.WebhookURL != "" {
		out.WebhookURL = ChannelRedacted
	}
	return out
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
