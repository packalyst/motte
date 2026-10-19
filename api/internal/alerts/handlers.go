package alerts

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// Handlers maps endpoint names (endpoints.json) to HTTP handlers. Delivery channels + SMTP live in
// the notifications (pwa) service now; this service owns only the per-user rules.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetRules":   s.handleGetRules,
		"CreateRule": s.handleCreateRule,
		"UpdateRule": s.handleUpdateRule,
		"DeleteRule": s.handleDeleteRule,
	}
}

func callerID(r *http.Request) (int64, string) {
	if p := router.CurrentUser(r); p != nil {
		return p.UserID, p.Username
	}
	return 0, ""
}

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
		fmt.Sprintf("Alert rule %q (%s) created", out.Name, out.Metric))
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

// validateRule checks the shape and, for each specific machine target, that the caller may access
// it (scope). AllMachines needs no up-front check — the evaluator filters to the owner's scope.
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
	if !rule.Targets.Host && !rule.Targets.AllMachines && len(rule.Targets.MachineIDs) == 0 {
		return fmt.Errorf("select at least one target")
	}
	p := router.CurrentUser(r)
	for _, id := range rule.Targets.MachineIDs {
		if !s.machineExists(id) {
			return fmt.Errorf("unknown machine")
		}
		if !s.machineAccessible(p, id) {
			return fmt.Errorf("a selected machine is outside your scope")
		}
	}
	return nil
}

func (s *Service) machineExists(id string) bool {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM fleet_machines WHERE id = ?`, id).Scan(&n)
	return n > 0
}

// machineAccessible checks a single machine against the caller's scope (source of truth:
// fleet/scope.go), reading the machine's tags from the DB.
func (s *Service) machineAccessible(p *router.Principal, machineID string) bool {
	if p == nil {
		return false
	}
	var tagsCSV string
	s.db.QueryRow(`SELECT COALESCE(tags, '') FROM fleet_machines WHERE id = ?`, machineID).Scan(&tagsCSV)
	return scopeAllowsMachineRaw(p.Role, p.ScopeKind, p.ScopeValues, machineID, tagsCSV)
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
