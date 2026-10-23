package fleet

import "testing"

// CVE search is literal: % and _ in the query match themselves, not "anything".
func TestCVESearchIsLiteral(t *testing.T) {
	svc := newTestService(t)
	for _, r := range [][2]string{{"CVE-2026-0001", "openssl"}, {"CVE-2026-0002", "lib_ssl"}} {
		if _, err := svc.db.Exec(`INSERT INTO fleet_cves (machine_id, cve_id, pkg, installed, fixed, severity, target, project, class, type, title, scanned_at) VALUES ('m1', ?, ?, '1.0', '1.1', 'HIGH', 'os', 'OS', 'os-pkgs', 'debian', 'test', '')`, r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	for q, want := range map[string]int{"%": 0, "ssl": 2, "lib_": 1, "b_s": 1, "0001": 1} {
		if _, n, err := svc.ListCVEs("m1", cveFilter{Q: q}); err != nil || n != want {
			t.Errorf("ListCVEs q=%q: got %d (err %v), want %d", q, n, err, want)
		}
		if _, n, err := svc.ListCVEsByCVE("m1", cveFilter{Q: q}); err != nil || n != want {
			t.Errorf("ListCVEsByCVE q=%q: got %d (err %v), want %d", q, n, err, want)
		}
	}
}
