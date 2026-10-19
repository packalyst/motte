package pwa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"api/internal/helper"
)

// This file makes webhook + email first-class delivery channels alongside push, for EVERY
// notification type. Push keeps its existing subscription-based path (SendNotification /
// SendNotificationToUser); these helpers add webhook/email on top, gated by the same per-event
// preferences.

// prefEnabled reports whether the user wants notifType, honoring PreferenceDefaults when the user
// has no explicit row.
func (s *Service) prefEnabled(userID int64, notifType NotificationType) bool {
	def := 1
	if v, ok := PreferenceDefaults[notifType]; ok && !v {
		def = 0
	}
	var enabled int
	err := s.db.QueryRow(`SELECT COALESCE(enabled, ?) FROM users_notification_preferences WHERE user_id = ? AND pref_key = ?`,
		def, userID, string(notifType)).Scan(&enabled)
	if err != nil {
		return def == 1
	}
	return enabled == 1
}

func webhookPayload(notifType NotificationType, notif *Notification) map[string]interface{} {
	p := map[string]interface{}{
		"type":  string(notifType),
		"title": notif.Title,
		"body":  notif.Body,
		"time":  time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range notif.Data {
		if _, exists := p[k]; !exists {
			p[k] = v
		}
	}
	return p
}

// deliverChannels sends to a user's stored webhook + email (NOT push). The caller has already
// decided the user should be notified. Best-effort per channel.
func (s *Service) deliverChannels(userID int64, notifType NotificationType, notif *Notification) {
	ch, err := s.GetChannels(userID)
	if err != nil {
		return
	}
	if ch.WebhookEnabled && ch.WebhookURL != "" {
		if err := postWebhook(ch.WebhookURL, webhookPayload(notifType, notif)); err != nil {
			log.Printf("pwa: webhook for user %d: %v", userID, err)
		}
	}
	if ch.EmailEnabled && ch.Email != "" {
		if err := sendEmail(ch.Email, notif.Title, notif.Body); err != nil {
			log.Printf("pwa: email for user %d: %v", userID, err)
		}
	}
}

// fanoutChannels delivers a BROADCAST event to webhook/email for every user who has one enabled
// and the event preference on. Push for broadcasts stays in SendNotification's subscription path;
// this only adds the non-push channels.
func (s *Service) fanoutChannels(notifType NotificationType, notif *Notification) {
	s.ensureChannelsTable()
	def := 1
	if v, ok := PreferenceDefaults[notifType]; ok && !v {
		def = 0
	}
	rows, err := s.db.Query(`
		SELECT c.user_id
		FROM notification_channels c
		LEFT JOIN users_notification_preferences p ON c.user_id = p.user_id AND p.pref_key = ?
		WHERE COALESCE(p.enabled, ?) = 1 AND (c.webhook_enabled = 1 OR c.email_enabled = 1)`,
		string(notifType), def)
	if err != nil {
		return
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		s.deliverChannels(id, notifType, notif)
	}
}

// DispatchToUser notifies ONE user of an event across all their channels (push + webhook + email),
// gated by their per-event preference. Used for per-user events such as resource alerts.
func (s *Service) DispatchToUser(userID int64, notifType NotificationType, notif *Notification) {
	if !s.prefEnabled(userID, notifType) {
		return
	}
	if subs, err := s.GetUserSubscriptions(userID); err == nil && len(subs) > 0 {
		if payload, perr := json.Marshal(notif); perr == nil {
			s.sendToSubscriptions(subs, payload)
		}
	}
	s.deliverChannels(userID, notifType, notif)
}

// postWebhook POSTs JSON through the SSRF-guarded client (a user's URL may be an internal
// self-hosted target like ntfy, but can never be steered to cloud-metadata/link-local).
func postWebhook(url string, payload interface{}) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := helper.SafeInternalHTTPClient(15 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
