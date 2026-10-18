package alerts

import (
	"testing"
	"time"
)

func TestStepRuleDebounce(t *testing.T) {
	st := &ruleState{}
	base := time.Now()

	// Below threshold: never fires.
	if stepRule(st, 50, 90, 5, base) {
		t.Fatal("should not fire below threshold")
	}
	// Above threshold but duration not yet met.
	if stepRule(st, 95, 90, 5, base.Add(1*time.Minute)) {
		t.Fatal("should not fire before the sustained duration")
	}
	// Still above and duration met → fire once.
	if !stepRule(st, 95, 90, 5, base.Add(6*time.Minute)) {
		t.Fatal("should fire after sustained breach")
	}
	// Still breached → no re-fire (debounced).
	if stepRule(st, 97, 90, 5, base.Add(7*time.Minute)) {
		t.Fatal("should not re-fire while still breached")
	}
	// Recover (drops under threshold) resets state.
	if stepRule(st, 10, 90, 5, base.Add(8*time.Minute)) {
		t.Fatal("recovery must not fire")
	}
	if !st.breachStart.IsZero() || st.firing {
		t.Fatal("state should reset on recovery")
	}
	// A fresh breach can fire again after the duration.
	stepRule(st, 95, 90, 5, base.Add(9*time.Minute))        // start breach
	if !stepRule(st, 95, 90, 5, base.Add(15*time.Minute)) { // sustained again
		t.Fatal("a new breach after recovery should fire")
	}
}

func TestStepRuleZeroDurationFiresImmediately(t *testing.T) {
	st := &ruleState{}
	if !stepRule(st, 91, 90, 0, time.Now()) {
		t.Fatal("forMin=0 should fire on the first breach")
	}
}

func TestValidate(t *testing.T) {
	if err := validate(Config{WebhookEnabled: true, WebhookURL: "ftp://x"}); err == nil {
		t.Error("non-http webhook URL should fail")
	}
	if err := validate(Config{Rules: []Rule{{Metric: "gpu", Threshold: 50}}}); err == nil {
		t.Error("unknown metric should fail")
	}
	if err := validate(Config{Rules: []Rule{{Metric: "cpu", Threshold: 150}}}); err == nil {
		t.Error("out-of-range threshold should fail")
	}
	if err := validate(Config{Rules: []Rule{{Metric: "disk", Threshold: 80, ForMin: 5}}, WebhookEnabled: true, WebhookURL: "https://hooks.example/x"}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestMaskedWebhook(t *testing.T) {
	if got := (Config{WebhookURL: "https://hooks.example/secret-token"}).masked().WebhookURL; got != redacted {
		t.Errorf("webhook URL not masked: %q", got)
	}
	if got := (Config{WebhookURL: ""}).masked().WebhookURL; got != "" {
		t.Errorf("empty webhook URL should stay empty, got %q", got)
	}
}
