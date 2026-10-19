package alerts

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"api/internal/auth"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

const redacted = "__stored__"

// Handlers maps endpoint names (endpoints.json) to HTTP handlers.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetRules":     s.handleGetRules,
		"CreateRule":   s.handleCreateRule,
		"UpdateRule":   s.handleUpdateRule,
		"DeleteRule":   s.handleDeleteRule,
		"GetChannels":  s.handleGetChannels,
		"SaveChannels": s.handleSaveChannels,
		"Test":         s.handleTest,
		"GetSMTP":      s.handleGetSMTP,
		"SaveSMTP":     s.handleSaveSMTP,
	}
}

func callerID(r *http.Request) (int64, string) {
	if p := router.CurrentUser(r); p != nil {
		return p.UserID, p.Username
	}
	return 0, ""
}

// ---- rules (per-user) ----

func (s *Service) handleGetRules(w http.ResponseWriter, r *http.Request) {
	uid, _ := callerID(r)
	rules, err := s.listRules(uid)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []Rule{}
	}
	router.JSON(w, rules)
}

func (s *Service) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	uid, actor := callerID(r)
	var in Rule
	if !router.DecodeJSONOrError(w, r, &in) {
		return
	}
	if err := s.validateRule(r, in); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, err := s.createRule(uid, in)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("alerts", "alert_rule_created", events.SeverityInfo, actor, helper.GetClientIP(r),
		fmt.Sprintf("Alert rule %q (%s %s) created", out.Name, out.Metric, out.Scope))
	router.JSON(w, out)
}

func (s *Service) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	uid, actor := callerID(r)
	id, err := strconv.ParseInt(router.ExtractPathParam(r, "/api/alerts/rules/"), 10, 64)
	if err != nil {
		router.JSONError(w, "invalid rule id", http.StatusBadRequest)
		return
	}
	var in Rule
	if !router.DecodeJSONOrError(w, r, &in) {
		return
	}
	if err := s.validateRule(r, in); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.updateRule(uid, id, in); err != nil {
		if errors.Is(err, errNotFound) {
			router.JSONError(w, "rule not found", http.StatusNotFound)
			return
		}
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("alerts", "alert_rule_updated", events.SeverityInfo, actor, helper.GetClientIP(r),
		fmt.Sprintf("Alert rule %d updated", id))
	router.JSON(w, map[string]bool{"ok": true})
}

func (s *Service) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	uid, actor := callerID(r)
	id, err := strconv.ParseInt(router.ExtractPathParam(r, "/api/alerts/rules/"), 10, 64)
	if err != nil {
		router.JSONError(w, "invalid rule id", http.StatusBadRequest)
		return
	}
	if err := s.deleteRule(uid, id); err != nil {
		if errors.Is(err, errNotFound) {
			router.JSONError(w, "rule not found", http.StatusNotFound)
			return
		}
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("alerts", "alert_rule_deleted", events.SeverityInfo, actor, helper.GetClientIP(r),
		fmt.Sprintf("Alert rule %d deleted", id))
	router.JSON(w, map[string]bool{"ok": true})
}

// validateRule checks the shape and, for machine-scoped rules, that the caller may access the
// machine (scope). Mirrors fleet/scope.go's scopeAllows for the machine case.
func (s *Service) validateRule(r *http.Request, rule Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if _, ok := metricLabel[rule.Metric]; !ok {
		return fmt.Errorf("unknown metric %q", rule.Metric)
	}
	if rule.Threshold < 0 || rule.Threshold > 100 {
		return fmt.Errorf("threshold must be 0-100")
	}
	if rule.ForMin < 0 {
		return fmt.Errorf("duration must be >= 0")
	}
	switch rule.Scope {
	case "host":
		return nil
	case "machine":
		if rule.MachineID == "" {
			return fmt.Errorf("a machine must be selected")
		}
		if !s.machineExists(rule.MachineID) {
			return fmt.Errorf("unknown machine")
		}
		if !s.machineAccessible(router.CurrentUser(r), rule.MachineID) {
			return fmt.Errorf("that machine is outside your scope")
		}
		return nil
	default:
		return fmt.Errorf("unknown scope %q", rule.Scope)
	}
}

func (s *Service) machineExists(id string) bool {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM fleet_machines WHERE id = ?`, id).Scan(&n)
	return n > 0
}

// machineAccessible replicates the fleet scope decision for a single machine (source of truth:
// fleet/scope.go scopeAllows) without importing the fleet service.
func (s *Service) machineAccessible(p *router.Principal, machineID string) bool {
	if p == nil {
		return false
	}
	if auth.RoleAtLeast(p.Role, auth.RoleAdmin) || p.ScopeKind == "" || p.ScopeKind == auth.ScopeAll {
		return true
	}
	switch p.ScopeKind {
	case auth.ScopeHost:
		for _, id := range splitCSV(p.ScopeValues) {
			if id == machineID {
				return true
			}
		}
	case auth.ScopeTag:
		var tagsCSV string
		if err := s.db.QueryRow(`SELECT COALESCE(tags, '') FROM fleet_machines WHERE id = ?`, machineID).Scan(&tagsCSV); err != nil {
			return false
		}
		have := map[string]bool{}
		for _, t := range splitCSV(tagsCSV) {
			have[t] = true
		}
		for _, want := range splitCSV(p.ScopeValues) {
			if have[want] {
				return true
			}
		}
	}
	return false
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---- channels (per-user) ----

func (s *Service) handleGetChannels(w http.ResponseWriter, r *http.Request) {
	uid, _ := callerID(r)
	ch, err := s.getChannels(uid)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, ch.masked())
}

func (s *Service) handleSaveChannels(w http.ResponseWriter, r *http.Request) {
	uid, actor := callerID(r)
	var in Channels
	if !router.DecodeJSONOrError(w, r, &in) {
		return
	}
	stored, err := s.getChannels(uid)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if in.WebhookURL == redacted { // write-only: keep the stored secret
		in.WebhookURL = stored.WebhookURL
	}
	if err := validateChannels(in); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.saveChannels(uid, in); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("alerts", "alert_channels_changed", events.SeverityInfo, actor, helper.GetClientIP(r), "Alert delivery channels updated")
	router.JSON(w, in.masked())
}

func (c Channels) masked() Channels {
	out := c
	if c.WebhookURL != "" {
		out.WebhookURL = redacted
	}
	return out
}

func validateChannels(c Channels) error {
	if c.WebhookEnabled {
		u := strings.TrimSpace(c.WebhookURL)
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("webhook URL must be an http(s) URL")
		}
	}
	if c.EmailEnabled && !strings.Contains(c.Email, "@") {
		return fmt.Errorf("a valid email address is required")
	}
	return nil
}

// handleTest delivers a synthetic alert to the caller via the posted channel settings (webhook
// secret merged with the stored one) so the form can be tested before saving.
func (s *Service) handleTest(w http.ResponseWriter, r *http.Request) {
	uid, _ := callerID(r)
	var in Channels
	_ = router.DecodeJSON(r, &in)
	stored, _ := s.getChannels(uid)
	if in.WebhookURL == redacted || in.WebhookURL == "" {
		in.WebhookURL = stored.WebhookURL
	}
	if in.Email == "" {
		in.Email = stored.Email
	}
	if !in.PushEnabled && !in.WebhookEnabled && !in.EmailEnabled {
		router.JSONError(w, "enable a channel to test", http.StatusBadRequest)
		return
	}
	s.deliver(uid, in, "Test alert", "This is a test resource alert from your panel.", map[string]interface{}{
		"type": "resource_alert", "rule": "Test alert", "metric": "cpu", "value": 99, "threshold": 90, "test": true,
	})
	router.JSON(w, map[string]bool{"ok": true})
}

// ---- SMTP (global, admin) ----

func (s *Service) handleGetSMTP(w http.ResponseWriter, r *http.Request) {
	c := loadSMTP()
	if c.Pass != "" {
		c.Pass = redacted // write-only
	}
	router.JSON(w, c)
}

func (s *Service) handleSaveSMTP(w http.ResponseWriter, r *http.Request) {
	_, actor := callerID(r)
	var in smtpConfig
	if !router.DecodeJSONOrError(w, r, &in) {
		return
	}
	if in.Pass == redacted {
		in.Pass = "" // keep stored (saveSMTP leaves it untouched on empty)
	}
	if err := saveSMTP(in); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events.Audit("alerts", "smtp_config_changed", events.SeverityInfo, actor, helper.GetClientIP(r), "SMTP settings updated")
	router.JSON(w, map[string]bool{"ok": true})
}
