// Package alerts fires notifications when a host resource (CPU, memory, disk) stays above a
// configured threshold for a sustained period. Alerts go to an outbound webhook (admin-configured,
// SSRF-guarded) and/or the existing PWA push channel. Rules + the webhook URL are stored encrypted
// at rest; the evaluator samples independently of the dashboard WS so it works unattended.
package alerts

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"api/internal/auth/pwa"
	"api/internal/database"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/routines"
	"api/internal/serverstats"
)

const evalInterval = 60 * time.Second

// Rule is one threshold condition.
type Rule struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Metric    string  `json:"metric"`    // "cpu" | "mem" | "disk"
	Threshold float64 `json:"threshold"` // percent (0-100)
	ForMin    int     `json:"forMin"`    // sustained minutes above threshold before firing
	Enabled   bool    `json:"enabled"`
}

// Config is the alerting policy, persisted as one encrypted JSON blob.
type Config struct {
	Rules          []Rule `json:"rules"`
	WebhookURL     string `json:"webhookUrl"` // sensitive (often carries a token) → write-only to UI
	WebhookEnabled bool   `json:"webhookEnabled"`
	PushEnabled    bool   `json:"pushEnabled"`
}

type ruleState struct {
	breachStart time.Time
	firing      bool
	lastFired   time.Time
}

// Service owns the config, the evaluator loop, and per-rule breach state.
type Service struct {
	db      *database.DB
	mu      sync.Mutex
	st      map[string]*ruleState // ruleID -> state
	cfgOnce sync.Once
}

func New() (*Service, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}
	return &Service{db: db, st: map[string]*ruleState{}}, nil
}

func (s *Service) ensureTable() {
	s.cfgOnce.Do(func() {
		s.db.Exec(`CREATE TABLE IF NOT EXISTS alert_config (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			config_enc TEXT NOT NULL
		)`)
	})
}

func (s *Service) load() (Config, error) {
	s.ensureTable()
	var enc string
	err := s.db.QueryRow("SELECT config_enc FROM alert_config WHERE id = 1").Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}
	plain, err := helper.Decrypt(enc)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal([]byte(plain), &c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (s *Service) save(c Config) error {
	s.ensureTable()
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	enc, err := helper.Encrypt(string(raw))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO alert_config (id, config_enc) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET config_enc = excluded.config_enc`, enc)
	return err
}

// Start runs the evaluator loop.
func (s *Service) Start() {
	routines.RegisterDaemon("alerts-evaluator", "Resource alerts: checks CPU/memory/disk thresholds and fires webhooks/push")
	go func() {
		t := time.NewTicker(evalInterval)
		defer t.Stop()
		for range t.C {
			s.evaluate()
		}
	}()
}

// evaluate samples the host once and checks every enabled rule, tracking sustained breaches and
// firing (once) when a rule has been over threshold for its full duration. A rule that drops back
// under threshold resets, so the next breach can fire again.
func (s *Service) evaluate() {
	cfg, err := s.load()
	if err != nil {
		return
	}
	var hasEnabled bool
	for _, r := range cfg.Rules {
		if r.Enabled {
			hasEnabled = true
			break
		}
	}
	if !hasEnabled {
		return
	}

	cpu, mem, disk := serverstats.Snapshot()
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	live := map[string]bool{}
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		live[r.ID] = true
		val, ok := metricValue(r.Metric, cpu, mem, disk)
		if !ok {
			continue
		}
		stt := s.st[r.ID]
		if stt == nil {
			stt = &ruleState{}
			s.st[r.ID] = stt
		}
		if stepRule(stt, val, r.Threshold, r.ForMin, now) {
			go s.fire(cfg, r, val) // network I/O off the lock
		}
	}
	// Drop state for rules that no longer exist.
	for id := range s.st {
		if !live[id] {
			delete(s.st, id)
		}
	}
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

// fire delivers one alert to the configured channels.
func (s *Service) fire(cfg Config, r Rule, value float64) {
	host, _ := os.Hostname()
	title := fmt.Sprintf("%s alert: %s", metricLabel[r.Metric], r.Name)
	body := fmt.Sprintf("%s is at %.0f%% (threshold %.0f%% for %d min) on %s", metricLabel[r.Metric], value, r.Threshold, r.ForMin, host)

	if cfg.WebhookEnabled && cfg.WebhookURL != "" {
		if err := postWebhook(cfg.WebhookURL, map[string]interface{}{
			"type": "resource_alert", "rule": r.Name, "metric": r.Metric,
			"value": value, "threshold": r.Threshold, "host": host,
			"time": time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			log.Printf("alerts: webhook failed: %v", err)
		}
	}
	if cfg.PushEnabled {
		if p := pwa.Get(); p != nil {
			p.NotifySystemAlert(title, body)
		}
	}
	events.Audit("alerts", "alert_fired", events.SeverityWarning, "", "", body)
}

// postWebhook POSTs JSON through the SSRF-guarded client (admin-configured URL may be internal,
// but can never be steered to cloud-metadata/link-local).
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
