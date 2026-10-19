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

func TestValidateChannels(t *testing.T) {
	if err := validateChannels(Channels{WebhookEnabled: true, WebhookURL: "ftp://x"}); err == nil {
		t.Error("non-http webhook URL should fail")
	}
	if err := validateChannels(Channels{EmailEnabled: true, Email: "not-an-email"}); err == nil {
		t.Error("invalid email should fail")
	}
	if err := validateChannels(Channels{WebhookEnabled: true, WebhookURL: "https://hooks.example/x", EmailEnabled: true, Email: "a@b.co"}); err != nil {
		t.Errorf("valid channels rejected: %v", err)
	}
}

func TestMaskedWebhook(t *testing.T) {
	if got := (Channels{WebhookURL: "https://hooks.example/secret-token"}).masked().WebhookURL; got != redacted {
		t.Errorf("webhook URL not masked: %q", got)
	}
	if got := (Channels{WebhookURL: ""}).masked().WebhookURL; got != "" {
		t.Errorf("empty webhook URL should stay empty, got %q", got)
	}
}
