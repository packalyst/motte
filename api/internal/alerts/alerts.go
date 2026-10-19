// Package alerts fires notifications when a resource (CPU, memory, disk) stays above a threshold
// for a sustained period. Rules are PER-USER (see store.go); each rule targets the panel host
// and/or one or more fleet machines (and/or "all machines the owner can see"). Delivery is handled
// by the notifications (pwa) package, which routes a resource_alert to the owner's push devices,
// webhook and/or email according to their channels + preference. The evaluator samples
// independently of the dashboard WS so it works unattended.
package alerts

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"api/internal/auth"
	"api/internal/database"
	"api/internal/routines"
	"api/internal/serverstats"
)

const evalInterval = 60 * time.Second

// Targets is which subjects a rule watches.
type Targets struct {
	Host        bool     `json:"host"`        // the panel host
	AllMachines bool     `json:"allMachines"` // every fleet machine the owner can see
	MachineIDs  []string `json:"machineIds"`  // specific fleet machines
}

// Rule is one per-user threshold condition.
type Rule struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	Metric    string  `json:"metric"` // "cpu" | "mem" | "disk"
	Targets   Targets `json:"targets"`
	Threshold float64 `json:"threshold"` // percent (0-100)
	ForMin    int     `json:"forMin"`    // sustained minutes above threshold before firing
	Enabled   bool    `json:"enabled"`
	UserID    int64   `json:"-"` // owner; never serialized to the client
}

type ruleState struct {
	breachStart time.Time
	firing      bool
	lastFired   time.Time
}

// Service owns the evaluator loop and per-(rule,target) breach state.
type Service struct {
	db      *database.DB
	mu      sync.Mutex
	st      map[string]*ruleState // stateKey -> state
	cfgOnce sync.Once
}

func New() (*Service, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}
	return &Service{db: db, st: map[string]*ruleState{}}, nil
}

// Start runs the evaluator loop.
func (s *Service) Start() {
	routines.RegisterDaemon("alerts-evaluator", "Resource alerts: checks CPU/memory/disk thresholds (host + fleet) and notifies the owning user")
	go func() {
		t := time.NewTicker(evalInterval)
		defer t.Stop()
		for range t.C {
			s.evaluate()
		}
	}()
}

// target is one concrete subject a rule is evaluated against.
type target struct {
	kind  string // "host" | "machine"
	id    string // machine id when kind=="machine"
	label string // human label for the alert text
}

func (s *Service) expandTargets(r Rule) []target {
	var out []target
	seen := map[string]bool{}
	add := func(t target) {
		k := t.kind + ":" + t.id
		if !seen[k] {
			seen[k] = true
			out = append(out, t)
		}
	}
	if r.Targets.Host {
		add(target{kind: "host", id: "", label: "this panel"})
	}
	ids := append([]string{}, r.Targets.MachineIDs...)
	if r.Targets.AllMachines {
		ids = append(ids, s.accessibleMachineIDs(r.UserID)...)
	}
	for _, id := range ids {
		add(target{kind: "machine", id: id, label: s.machineNameOr(id)})
	}
	return out
}

func stateKey(ruleID int64, t target) string {
	return strconv.FormatInt(ruleID, 10) + ":" + t.kind + ":" + t.id
}

// evaluate samples each enabled rule's metric for each of its targets and tracks sustained
// breaches, firing (once) when a (rule,target) has been over threshold for its full duration.
func (s *Service) evaluate() {
	rules, err := s.listRules(0) // all enabled rules across users
	if err != nil || len(rules) == 0 {
		return
	}

	var cpu, mem, disk float64
	var hostSampled bool
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	live := map[string]bool{}
	for _, r := range rules {
		for _, t := range s.expandTargets(r) {
			var val float64
			var ok bool
			if t.kind == "machine" {
				val, ok = s.latestMachineMetric(t.id, r.Metric)
			} else {
				if !hostSampled {
					cpu, mem, disk = serverstats.Snapshot()
					hostSampled = true
				}
				val, ok = metricValue(r.Metric, cpu, mem, disk)
			}
			if !ok {
				continue
			}
			key := stateKey(r.ID, t)
			live[key] = true
			stt := s.st[key]
			if stt == nil {
				stt = &ruleState{}
				s.st[key] = stt
			}
			if stepRule(stt, val, r.Threshold, r.ForMin, now) {
				go s.fire(r, t.label, val)
			}
		}
	}
	for k := range s.st {
		if !live[k] {
			delete(s.st, k)
		}
	}
}

// latestMachineMetric reads a fleet machine's most recent reported value for the metric. Reads the
// fleet_metrics table directly (no fleet-package coupling); ok=false when it has never reported.
func (s *Service) latestMachineMetric(machineID, metric string) (float64, bool) {
	col := map[string]string{"cpu": "cpu_avg", "mem": "mem_avg", "disk": "disk_avg"}[metric]
	if col == "" || machineID == "" {
		return 0, false
	}
	var v sql.NullFloat64
	err := s.db.QueryRow(
		`SELECT `+col+` FROM fleet_metrics WHERE machine_id = ? ORDER BY bucket DESC LIMIT 1`, machineID,
	).Scan(&v)
	if err != nil || !v.Valid {
		return 0, false
	}
	return v.Float64, true
}

func (s *Service) machineNameOr(machineID string) string {
	var name string
	if err := s.db.QueryRow(`SELECT name FROM fleet_machines WHERE id = ?`, machineID).Scan(&name); err != nil || name == "" {
		return machineID
	}
	return name
}

// accessibleMachineIDs returns the fleet machine IDs the rule owner may see (for AllMachines),
// using the same scope rule as fleet/scope.go.
func (s *Service) accessibleMachineIDs(userID int64) []string {
	var role, kind, values string
	if err := s.db.QueryRow(`SELECT role, scope_kind, scope_values FROM users WHERE id = ?`, userID).Scan(&role, &kind, &values); err != nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, COALESCE(tags, '') FROM fleet_machines WHERE revoked = 0`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, tags string
		if rows.Scan(&id, &tags) != nil {
			continue
		}
		if scopeAllowsMachineRaw(role, kind, values, id, tags) {
			out = append(out, id)
		}
	}
	return out
}

// stepRule advances one (rule,target) breach state for a single sample and reports whether to fire
// now. Fires once when the value has stayed above threshold for the full duration, then stays quiet
// until it drops back under (debounce). Pure (no I/O) so it is unit-testable.
func stepRule(stt *ruleState, value, threshold float64, forMin int, now time.Time) bool {
	if value <= threshold {
		stt.breachStart = time.Time{}
		stt.firing = false
		return false
	}
	if stt.breachStart.IsZero() {
		stt.breachStart = now
	}
	if now.Sub(stt.breachStart) >= time.Duration(forMin)*time.Minute && !stt.firing {
		stt.firing = true
		stt.lastFired = now
		return true
	}
	return false
}

func metricValue(metric string, cpu, mem, disk float64) (float64, bool) {
	switch metric {
	case "cpu":
		return cpu, true
	case "mem":
		return mem, true
	case "disk":
		return disk, true
	default:
		return 0, false
	}
}

var metricLabel = map[string]string{"cpu": "CPU", "mem": "Memory", "disk": "Disk"}

func alertText(r Rule, target string, value float64) (title, body string) {
	title = fmt.Sprintf("%s alert: %s", metricLabel[r.Metric], r.Name)
	body = fmt.Sprintf("%s is at %.0f%% (threshold %.0f%% for %d min) on %s",
		metricLabel[r.Metric], value, r.Threshold, r.ForMin, target)
	return title, body
}

// scopeAllowsMachineRaw mirrors fleet/scope.go scopeAllows for a single machine, from raw columns
// (so both the request path and the unattended evaluator can use it).
func scopeAllowsMachineRaw(role, scopeKind, scopeValues, machineID, machineTagsCSV string) bool {
	if auth.RoleAtLeast(role, auth.RoleAdmin) || scopeKind == "" || scopeKind == auth.ScopeAll {
		return true
	}
	switch scopeKind {
	case auth.ScopeHost:
		for _, id := range splitCSV(scopeValues) {
			if id == machineID {
				return true
			}
		}
	case auth.ScopeTag:
		have := map[string]bool{}
		for _, t := range splitCSV(machineTagsCSV) {
			have[t] = true
		}
		for _, want := range splitCSV(scopeValues) {
			if have[want] {
				return true
			}
		}
	}
	return false
}

// marshalTargets / parseTargets persist Targets as a JSON column.
func marshalTargets(t Targets) string {
	b, _ := json.Marshal(t)
	return string(b)
}

func parseTargets(s string) Targets {
	var t Targets
	if s != "" {
		json.Unmarshal([]byte(s), &t)
	}
	return t
}
