package alerts

import (
	"fmt"
	"net/http"
	"strings"

	"api/internal/auth/pwa"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

const redacted = "__stored__"

// Handlers maps endpoint names (endpoints.json) to HTTP handlers.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetConfig":  s.handleGetConfig,
		"SaveConfig": s.handleSaveConfig,
		"Test":       s.handleTest,
	}
}

func (c Config) masked() Config {
	out := c
	if c.WebhookURL != "" {
		out.WebhookURL = redacted // often carries a token
	}
	return out
}

func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.load()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, cfg.masked())
}

func (s *Service) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	var incoming Config
	if !router.DecodeJSONOrError(w, r, &incoming) {
		return
	}
	stored, err := s.load()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if incoming.WebhookURL == redacted {
		incoming.WebhookURL = stored.WebhookURL // write-only: blank/redacted keeps stored
	}
	if err := validate(incoming); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.save(incoming); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("alerts", "alert_config_changed", events.SeverityInfo, actorOf(r), helper.GetClientIP(r),
		fmt.Sprintf("Alert configuration updated (%d rule(s))", len(incoming.Rules)))
	router.JSON(w, incoming.masked())
}

func validate(c Config) error {
	if c.WebhookEnabled {
		u := strings.TrimSpace(c.WebhookURL)
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("webhook URL must be an http(s) URL")
		}
	}
	for _, r := range c.Rules {
		if _, ok := metricLabel[r.Metric]; !ok {
			return fmt.Errorf("unknown metric %q", r.Metric)
		}
		if r.Threshold < 0 || r.Threshold > 100 {
			return fmt.Errorf("threshold must be 0-100")
		}
		if r.ForMin < 0 {
			return fmt.Errorf("duration must be >= 0")
		}
	}
	return nil
}

// handleTest fires a synthetic alert to the configured channels so an operator can confirm
// delivery. It uses the posted webhook toggle/URL (merged with the stored secret) so the form can
// be tested before saving.
func (s *Service) handleTest(w http.ResponseWriter, r *http.Request) {
	var req Config
	_ = router.DecodeJSON(r, &req)
	stored, _ := s.load()
	if req.WebhookURL == redacted || req.WebhookURL == "" {
		req.WebhookURL = stored.WebhookURL
	}

	result := map[string]string{}
	if req.WebhookEnabled && req.WebhookURL != "" {
		if err := postWebhook(req.WebhookURL, map[string]interface{}{
			"type": "resource_alert", "rule": "Test alert", "metric": "cpu",
			"value": 99, "threshold": 90, "host": "panel", "test": true,
		}); err != nil {
			result["webhook"] = "failed: " + err.Error()
		} else {
			result["webhook"] = "sent"
		}
	}
	if req.PushEnabled {
		if p := pwa.Get(); p != nil {
			p.NotifySystemAlert("Test alert", "This is a test resource alert from your panel.")
			result["push"] = "sent"
		} else {
			result["push"] = "unavailable"
		}
	}
	if len(result) == 0 {
		router.JSONError(w, "no channel enabled to test", http.StatusBadRequest)
		return
	}
	router.JSON(w, result)
}

func actorOf(r *http.Request) string {
	if p := router.CurrentUser(r); p != nil {
		return p.Username
	}
	return ""
}
