package fleet

import (
	"encoding/json"
	"testing"
	"time"
)

// A partial report keeps the sections the agent left out (unchanged) from the stored report;
// a full report replaces them; the partial flag itself is never stored.
func TestMergePartialReport(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", time.Second)

	stored := `{"metrics":{"cpu":1},"cves":{"total":3},"facts":{"kernel":"6.1"},"intrusion":{"n":1}}`
	if _, err := svc.db.Exec(`UPDATE fleet_machines SET last_report = ? WHERE id = 'm1'`, stored); err != nil {
		t.Fatal(err)
	}

	out, err := svc.mergePartialReport("m1", []byte(`{"metrics":{"cpu":9},"partial":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	_ = json.Unmarshal(out, &got)
	if string(got["metrics"]) != `{"cpu":9}` || string(got["cves"]) != `{"total":3}` ||
		string(got["facts"]) != `{"kernel":"6.1"}` || string(got["intrusion"]) != `{"n":1}` {
		t.Fatalf("partial merge: %s", out)
	}
	if _, has := got["partial"]; has {
		t.Fatal("partial flag must not be stored")
	}

	// A full report (no flag) is stored as sent: a section it lacks is really gone.
	full := []byte(`{"metrics":{"cpu":2},"facts":{"kernel":"6.2"}}`)
	if out, _ := svc.mergePartialReport("m1", full); string(out) != string(full) {
		t.Fatalf("full report changed: %s", out)
	}

	// No stored report yet: the partial one is kept as is, minus the flag.
	addMachine(t, svc, "m2", time.Second)
	if out, _ := svc.mergePartialReport("m2", []byte(`{"metrics":{},"partial":true}`)); string(out) != `{"metrics":{}}` {
		t.Fatalf("no stored report: %s", out)
	}
	if _, err := svc.mergePartialReport("m1", []byte(`[1]`)); err == nil {
		t.Fatal("non-object report must be rejected")
	}
}
