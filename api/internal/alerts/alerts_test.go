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

func TestScopeAllowsMachineRaw(t *testing.T) {
	// owner/admin see everything regardless of scope.
	if !scopeAllowsMachineRaw("owner", "host", "other", "m1", "") {
		t.Error("owner should access any machine")
	}
	// host scope: only listed ids.
	if !scopeAllowsMachineRaw("operator", "host", "m1,m2", "m1", "") {
		t.Error("host scope should allow a listed id")
	}
	if scopeAllowsMachineRaw("operator", "host", "m2", "m1", "") {
		t.Error("host scope should reject an unlisted id")
	}
	// tag scope: intersection of machine tags and scope values.
	if !scopeAllowsMachineRaw("viewer", "tag", "prod", "m1", "prod,edge") {
		t.Error("tag scope should allow when tags intersect")
	}
	if scopeAllowsMachineRaw("viewer", "tag", "prod", "m1", "dev") {
		t.Error("tag scope should reject when tags do not intersect")
	}
}

func TestParseMarshalTargets(t *testing.T) {
	in := Targets{Host: true, MachineIDs: []string{"m1", "m2"}}
	got := parseTargets(marshalTargets(in))
	if !got.Host || len(got.MachineIDs) != 2 {
		t.Errorf("round-trip lost data: %+v", got)
	}
	if z := parseTargets(""); z.Host || z.AllMachines || len(z.MachineIDs) != 0 {
		t.Errorf("empty targets should be zero value, got %+v", z)
	}
}
