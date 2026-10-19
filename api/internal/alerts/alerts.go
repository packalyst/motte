// Package alerts fires notifications when a resource (CPU, memory, disk) stays above a threshold
// for a sustained period. Rules and delivery channels are PER-USER (each admin owns their own,
// see store.go) — delivered to that user's push devices, their own webhook, and/or email. A rule
// is scoped to the panel host or to a specific fleet machine. The evaluator samples independently
// of the dashboard WS so it works unattended.
package alerts

import (
	"database/sql"
	"fmt"
	"strconv"
	"sync"
	"time"

	"api/internal/database"
	"api/internal/routines"
	"api/internal/serverstats"
)

const evalInterval = 60 * time.Second

// Rule is one per-user threshold condition.
type Rule struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	Metric    string  `json:"metric"`    // "cpu" | "mem" | "disk"
	Scope     string  `json:"scope"`     // "host" (the panel box) | "machine" (a fleet machine)
	MachineID string  `json:"machineId"` // when scope == "machine"
	Threshold float64 `json:"threshold"` // percent (0-100)
	ForMin    int     `json:"forMin"`    // sustained minutes above threshold before firing
	Enabled   bool    `json:"enabled"`
	UserID    int64   `json:"-"` // owner; never serialized to the client
}

// Channels is one user's delivery configuration.
type Channels struct {
	WebhookURL     string `json:"webhookUrl"` // sensitive → write-only to the UI
	WebhookEnabled bool   `json:"webhookEnabled"`
	Email          string `json:"email"`
	EmailEnabled   bool   `json:"emailEnabled"`
	PushEnabled    bool   `json:"pushEnabled"`
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

func ruleKey(id int64) string { return strconv.FormatInt(id, 10) }

// evaluate samples each enabled rule's metric for its scope and tracks sustained breaches, firing
// (once) when a rule has been over threshold for its full duration. Host metrics are sampled once;
// machine metrics come from the latest fleet report.
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
		var val float64
		var ok bool
		switch r.Scope {
		case "machine":
			val, ok = s.latestMachineMetric(r.MachineID, r.Metric)
		default: // "host"
			if !hostSampled {
				cpu, mem, disk = serverstats.Snapshot()
				hostSampled = true
			}
			val, ok = metricValue(r.Metric, cpu, mem, disk)
		}
		if !ok {
			continue
		}
		key := ruleKey(r.ID)
		live[key] = true
		stt := s.st[key]
		if stt == nil {
			stt = &ruleState{}
			s.st[key] = stt
		}
		if stepRule(stt, val, r.Threshold, r.ForMin, now) {
			go s.fire(r, val) // network I/O off the lock
		}
	}
	for k := range s.st {
		if !live[k] {
			delete(s.st, k)
		}
	}
}

// latestMachineMetric reads a fleet machine's most recent reported value for the metric. Reads the
// fleet_metrics table directly (no fleet-package coupling); returns ok=false when the machine has
// never reported.
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

// stepRule advances one rule's breach state for a single sample and reports whether to fire now.
// It fires once when the value has stayed above threshold for the full duration, and stays quiet
// until the value drops back under threshold (debounce) — so a sustained breach is one alert, not
// a storm. Pure (no I/O) so the state machine is unit-testable.
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

// scopeTarget describes a rule's subject for the alert text.
func (s *Service) scopeTarget(r Rule) string {
	if r.Scope == "machine" {
		if name := s.machineName(r.MachineID); name != "" {
			return name
		}
		return r.MachineID
	}
	return "this panel"
}

func (s *Service) machineName(machineID string) string {
	var name string
	if err := s.db.QueryRow(`SELECT name FROM fleet_machines WHERE id = ?`, machineID).Scan(&name); err != nil {
		return ""
	}
	return name
}

// alertText builds the title/body for a fired rule.
func alertText(r Rule, target string, value float64) (title, body string) {
	title = fmt.Sprintf("%s alert: %s", metricLabel[r.Metric], r.Name)
	body = fmt.Sprintf("%s is at %.0f%% (threshold %.0f%% for %d min) on %s",
		metricLabel[r.Metric], value, r.Threshold, r.ForMin, target)
	return title, body
}
