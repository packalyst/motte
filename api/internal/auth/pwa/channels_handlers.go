package pwa

import (
	"encoding/json"
	"net/http"
	"strings"

	"api/internal/router"
)

func currentUID(r *http.Request) int64 {
	if p := router.CurrentUser(r); p != nil {
		return p.UserID
	}
	return 0
}

// handleChannels is GET/PUT /api/pwa/channels — the caller's own webhook/email delivery settings.
func (s *Service) handleChannels(w http.ResponseWriter, r *http.Request) {
	uid := currentUID(r)
	switch r.Method {
	case http.MethodGet:
		ch, err := s.GetChannels(uid)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		router.JSON(w, ch.Masked())
	case http.MethodPut:
		var in Channels
		if !router.DecodeJSONOrError(w, r, &in) {
			return
		}
		stored, err := s.GetChannels(uid)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if in.WebhookURL == ChannelRedacted { // write-only: keep stored secret
			in.WebhookURL = stored.WebhookURL
		}
		if in.WebhookEnabled {
			u := strings.TrimSpace(in.WebhookURL)
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				router.JSONError(w, "webhook URL must be an http(s) URL", http.StatusBadRequest)
				return
			}
		}
		if in.EmailEnabled && !strings.Contains(in.Email, "@") {
			router.JSONError(w, "a valid email address is required", http.StatusBadRequest)
			return
		}
		if err := s.SaveChannels(uid, in); err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		router.JSON(w, in.Masked())
	default:
		router.JSONError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTestChannels delivers a test notification to the caller via the POSTED channel settings
// (webhook secret merged with stored), reporting per-channel results so the form can be verified
// before saving.
func (s *Service) handleTestChannels(w http.ResponseWriter, r *http.Request) {
	uid := currentUID(r)
	var in Channels
	_ = json.NewDecoder(r.Body).Decode(&in)
	stored, _ := s.GetChannels(uid)
	if in.WebhookURL == ChannelRedacted || in.WebhookURL == "" {
		in.WebhookURL = stored.WebhookURL
	}
	if in.Email == "" {
		in.Email = stored.Email
	}

	notif := &Notification{Title: "Test notification", Body: "This is a test from your panel.", Icon: DefaultNotificationIcon, Tag: "test", Data: map[string]string{"type": "test"}}
	res := map[string]string{}

	if subs, err := s.GetUserSubscriptions(uid); err == nil && len(subs) > 0 {
		if payload, perr := json.Marshal(notif); perr == nil {
			s.sendToSubscriptions(subs, payload)
			res["push"] = "sent"
		}
	} else {
		res["push"] = "no subscribed devices"
	}
	if in.WebhookEnabled && in.WebhookURL != "" {
		if err := postWebhook(in.WebhookURL, webhookPayload("test", notif)); err != nil {
			res["webhook"] = "failed: " + err.Error()
		} else {
			res["webhook"] = "sent"
		}
	}
	if in.EmailEnabled && in.Email != "" {
		if err := sendEmail(in.Email, notif.Title, notif.Body); err != nil {
			res["email"] = "failed: " + err.Error()
		} else {
			res["email"] = "sent"
		}
	}
	router.JSON(w, res)
}

// handleSMTP is GET/PUT /api/pwa/smtp — global mail-server settings (admin). Password write-only.
func (s *Service) handleSMTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := LoadSMTP()
		if c.Pass != "" {
			c.Pass = ChannelRedacted
		}
		router.JSON(w, c)
	case http.MethodPut:
		var in SMTPConfig
		if !router.DecodeJSONOrError(w, r, &in) {
			return
		}
		if in.Pass == ChannelRedacted {
			in.Pass = "" // keep stored
		}
		if err := SaveSMTP(in); err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		router.JSON(w, map[string]bool{"ok": true})
	default:
		router.JSONError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
