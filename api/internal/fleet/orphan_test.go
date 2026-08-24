package fleet

import "testing"

// sweepOrphans must remove child rows whose machine is gone, and leave rows belonging to
// a live machine untouched.
func TestSweepOrphansRemovesOnlyOrphans(t *testing.T) {
	svc := newTestService(t)
	db := svc.db

	// One live machine, one that never existed in the registry.
	if _, err := db.Exec(`INSERT INTO fleet_machines (id, name, machine_hash, cert_fp, wg_pubkey, status, enrolled_at, revoked)
		VALUES ('live', 'live', 'h', 'fp', 'wg', 'enrolled', '2026-01-01T00:00:00Z', 0)`); err != nil {
		t.Fatal(err)
	}
	// CVEs: one for the live machine, two for a ghost.
	db.Exec(`INSERT INTO fleet_cves (machine_id, cve_id) VALUES ('live','CVE-1')`)
	db.Exec(`INSERT INTO fleet_cves (machine_id, cve_id) VALUES ('ghost','CVE-2')`)
	db.Exec(`INSERT INTO fleet_cves (machine_id, cve_id) VALUES ('ghost','CVE-3')`)
	// A metrics row for the ghost too.
	db.Exec(`INSERT INTO fleet_metrics (machine_id, bucket, samples) VALUES ('ghost', 0, 1)`)

	removed := sweepOrphans(db)
	if removed != 3 {
		t.Fatalf("removed = %d, want 3 (2 cves + 1 metric)", removed)
	}

	var cves int
	db.QueryRow(`SELECT COUNT(*) FROM fleet_cves`).Scan(&cves)
	if cves != 1 {
		t.Fatalf("surviving cves = %d, want 1 (the live machine's)", cves)
	}
	var live string
	if err := db.QueryRow(`SELECT machine_id FROM fleet_cves`).Scan(&live); err != nil || live != "live" {
		t.Fatalf("survivor = %q err=%v, want the live machine's row", live, err)
	}
}
