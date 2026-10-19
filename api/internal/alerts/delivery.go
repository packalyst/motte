package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"api/internal/auth/pwa"
	"api/internal/events"
	"api/internal/helper"
)

// fire delivers one alert to the rule owner's enabled channels: push (their subscribed devices),
// their own webhook, and/or email. Each channel failure is logged but never blocks the others.
func (s *Service) fire(r Rule, value float64) {
	ch, err := s.getChannels(r.UserID)
	if err != nil {
		log.Printf("alerts: load channels for user %d: %v", r.UserID, err)
		return
	}
	target := s.scopeTarget(r)
	title, body := alertText(r, target, value)
	s.deliver(r.UserID, ch, title, body, map[string]interface{}{
		"type": "resource_alert", "rule": r.Name, "metric": r.Metric,
		"scope": r.Scope, "target": target, "value": value, "threshold": r.Threshold,
		"time": time.Now().UTC().Format(time.RFC3339),
	})
	events.Audit("alerts", "alert_fired", events.SeverityWarning, "", "", body)
}

// deliver pushes a built alert to whichever channels the user has enabled.
func (s *Service) deliver(userID int64, ch Channels, title, body string, webhookPayload map[string]interface{}) {
	if ch.PushEnabled {
		if p := pwa.Get(); p != nil {
			if err := p.SendNotificationToUser(userID, &pwa.Notification{Title: title, Body: body, Tag: "resource-alert"}); err != nil {
				log.Printf("alerts: push to user %d: %v", userID, err)
			}
		}
	}
	if ch.WebhookEnabled && ch.WebhookURL != "" {
		if err := postWebhook(ch.WebhookURL, webhookPayload); err != nil {
			log.Printf("alerts: webhook for user %d: %v", userID, err)
		}
	}
	if ch.EmailEnabled && ch.Email != "" {
		if err := sendEmail(ch.Email, title, body); err != nil {
			log.Printf("alerts: email to user %d: %v", userID, err)
		}
	}
}

// postWebhook POSTs JSON through the SSRF-guarded client (the user's URL may be an internal
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
