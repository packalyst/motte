package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

// seedMachineData gives a machine one row in every per-machine table and a console recording.
func seedMachineData(t *testing.T, svc *Service, id string) string {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO fleet_commands (id, machine_id, type, status, created_at) VALUES ('c-` + id + `', ?, 'rescan', 'done', '2026-01-01T00:00:00Z')`,
		`INSERT INTO fleet_cves (machine_id, cve_id) VALUES (?, 'CVE-1')`,
		`INSERT INTO fleet_scans (machine_id, scanned_at, trigger, status) VALUES (?, '2026-01-01T00:00:00Z', 'manual', 'ok')`,
		`INSERT INTO fleet_fim (machine_id, path) VALUES (?, '/etc/passwd')`,
		`INSERT INTO fleet_metrics (machine_id, bucket, samples) VALUES (?, 0, 1)`,
	} {
		if _, err := svc.db.Exec(q, id); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = svc.db.Exec(`UPDATE fleet_machines SET last_report = '{"metrics":{}}', tags = 'prod', last_ip = '10.0.0.5' WHERE id = ?`, id)
	r, _, err := openRecorder(&Machine{ID: id}, "7_a", 80, 24, recMeta{MachineID: id})
	if err != nil {
		t.Fatal(err)
	}
	r.event("o", "hello")
	r.close()
	return filepath.Join(recordDir(), recordFileName(id, "7_a"))
}

func rowsFor(t *testing.T, svc *Service, id string) int {
	t.Helper()
	total := 0
	for _, tbl := range machineDataTables {
		var n int
		_ = svc.db.QueryRow(`SELECT COUNT(*) FROM `+tbl+` WHERE machine_id = ?`, id).Scan(&n)
		total += n
	}
	return total
}

// Uninstalling deletes all of a machine's data and recordings, keeping only a marker row (name,
// dates); deleting removes the row too. Another machine's data is untouched.
func TestUninstallAndDeletePurgeEverything(t *testing.T) {
	useRecordStore(t)
	svc := newTestService(t)
	addMachine(t, svc, "gone", false)
	addMachine(t, svc, "gone2", false) // a prefix-sharing id: must not be caught by "gone"
	addMachine(t, svc, "keep", false)
	recGone := seedMachineData(t, svc, "gone")
	recGone2 := seedMachineData(t, svc, "gone2")
	recKeep := seedMachineData(t, svc, "keep")

	if err := svc.MarkUninstalled("gone"); err != nil {
		t.Fatal(err)
	}
	if n := rowsFor(t, svc, "gone"); n != 0 {
		t.Fatalf("uninstall left %d data rows", n)
	}
	if _, err := os.Stat(recGone); !os.IsNotExist(err) {
		t.Fatal("uninstall must delete the machine's recordings")
	}
	var name, status, report, tags string
	var revoked int
	if err := svc.db.QueryRow(`SELECT name, status, revoked, COALESCE(last_report,''), tags FROM fleet_machines WHERE id = 'gone'`).
		Scan(&name, &status, &revoked, &report, &tags); err != nil {
		t.Fatal(err)
	}
	if name != "gone" || status != "uninstalled" || revoked != 1 || report != "" || tags != "" {
		t.Fatalf("marker row wrong: name=%q status=%q revoked=%d report=%q tags=%q", name, status, revoked, report, tags)
	}

	if err := svc.DeleteMachine("gone2"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_machines WHERE id = 'gone2'`).Scan(&n)
	if n != 0 || rowsFor(t, svc, "gone2") != 0 {
		t.Fatal("delete must remove the row and all its data")
	}
	if _, err := os.Stat(recGone2); !os.IsNotExist(err) {
		t.Fatal("delete must remove the machine's recordings")
	}

	if rowsFor(t, svc, "keep") != len(machineDataTables) {
		t.Fatal("another machine's data was touched")
	}
	if _, err := os.Stat(recKeep); err != nil {
		t.Fatal("another machine's recording was removed")
	}
}
