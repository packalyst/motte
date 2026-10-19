package alerts

import (
	"api/internal/auth/pwa"
	"api/internal/events"
)

// fire delivers one resource alert to the rule owner through the shared notifications pipeline,
// which fans it out to the owner's enabled channels (push, webhook, email) honoring their
// resource-alert preference.
func (s *Service) fire(r Rule, targetLabel string, value float64) {
	title, body := alertText(r, targetLabel, value)
	if p := pwa.Get(); p != nil {
		p.DispatchToUser(r.UserID, pwa.NotifyResourceAlert, &pwa.Notification{
			Title: title,
			Body:  body,
			Tag:   "resource-alert",
			Data:  map[string]string{"metric": r.Metric, "target": targetLabel},
		})
	}
	events.Audit("alerts", "alert_fired", events.SeverityWarning, "", "", body)
}
