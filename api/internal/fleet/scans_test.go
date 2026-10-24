package fleet

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func scanAt(t time.Time) scanMeta {
	m := scanMeta{ScannedAt: t.UTC().Format(time.RFC3339), Trigger: "manual"}
	m.Cost.Seconds, m.Cost.PeakMem = 30, 1<<30
	return m
}

func cve(id, sev, fixed string) CVE {
	return CVE{CVEID: id, Pkg: "pkg-" + id, Severity: sev, Fixed: fixed, Class: "os-pkgs", Target: "debian"}
}

// What the agent claims is validated before it's stored and shown.
func TestScanMetaNormalize(t *testing.T) {
	at := time.Now().Add(-time.Hour).Truncate(time.Second)
	m := scanMeta{ScannedAt: at.In(time.FixedZone("CEST", 2*3600)).Format(time.RFC3339), Trigger: "<script>", Failed: true,
		Error: "line1\nline2\x1b[31m" + strings.Repeat("x", 400)}
	m.Cost.Seconds, m.Cost.PeakMem = -5, 1<<60
	if err := m.normalize(); err != nil {
		t.Fatal(err)
	}
	if m.ScannedAt != at.UTC().Format(time.RFC3339) || m.Trigger != "manual" || m.Cost.Seconds != 0 || m.Cost.PeakMem != 1<<44 {
		t.Fatalf("normalized: %+v", m)
	}
	if strings.ContainsAny(m.Error, "\n\x1b") || len([]rune(m.Error)) != scanErrorMax+1 {
		t.Fatalf("error not one capped printable line: %q", m.Error)
	}
	for _, bad := range []string{"", "yesterday", time.Now().Add(48 * time.Hour).Format(time.RFC3339)} {
		if (&scanMeta{ScannedAt: bad}).normalize() == nil {
			t.Errorf("accepted scanned_at %q", bad)
		}
	}
}

// A scan's summary, what changed against the previous one, a repeat that changes nothing,
// and a failure that keeps the findings.
func TestScanHistoryFlow(t *testing.T) {
	s := newTestService(t)
	t0 := time.Now().Add(-time.Hour)

	first := []CVE{cve("CVE-1", "CRITICAL", "1.1"), cve("CVE-1", "LOW", ""), cve("CVE-2", "HIGH", ""), cve("CVE-3", "MEDIUM", "2")}
	if err := s.IngestCVEs("m1", scanAt(t0), first); err != nil {
		t.Fatal(err)
	}
	second := []CVE{cve("CVE-2", "HIGH", ""), cve("CVE-4", "LOW", "")}
	m2 := scanAt(t0.Add(time.Minute))
	m2.Trigger = "kernel"
	if err := s.IngestCVEs("m1", m2, second); err != nil {
		t.Fatal(err)
	}
	// the agent resends its last scan after a restart: no second row, no churn
	if err := s.IngestCVEs("m1", m2, second); err != nil {
		t.Fatal(err)
	}
	fail := scanAt(t0.Add(2 * time.Minute))
	fail.Failed, fail.Error = true, "timed out after 2h0m0s"
	if err := s.RecordScanFailure("m1", fail); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ScanHistory("m1")
	if err != nil || len(rows) != 3 {
		t.Fatalf("history: %d rows, %v", len(rows), err)
	}
	f, sc, fi := rows[0], rows[1], rows[2]
	if f.Status != "failed" || f.Error != "timed out after 2h0m0s" {
		t.Fatalf("failed row: %+v", f)
	}
	if fi.CVEs != 3 || fi.Findings != 4 || fi.Critical != 1 || fi.High != 1 || fi.Medium != 1 || fi.Fixable != 2 || fi.New != nil {
		t.Fatalf("first scan (worst severity per CVE, no diff): %+v", fi)
	}
	if sc.Trigger != "kernel" || sc.New == nil || *sc.New != 1 || *sc.Fixed != 2 || sc.Seconds != 30 || sc.PeakMem != 1<<30 {
		t.Fatalf("second scan: %+v", sc)
	}
	newIDs, fixedIDs, err := s.ScanChanges("m1", sc.ScannedAt)
	if err != nil || strings.Join(newIDs, ",") != "CVE-4" || strings.Join(fixedIDs, ",") != "CVE-1,CVE-3" {
		t.Fatalf("changes: new %v fixed %v %v", newIDs, fixedIDs, err)
	}
	// the failure left the second scan's findings in place
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM fleet_cves WHERE machine_id = 'm1'`).Scan(&n)
	if n != 2 {
		t.Fatalf("findings after a failed scan: %d, want 2", n)
	}
}

func TestScanHistoryRetention(t *testing.T) {
	s := newTestService(t)
	old := scanAt(time.Now().Add(-scanHistoryAge - time.Hour))
	old.Failed, old.Error = true, "x"
	if err := s.RecordScanFailure("m1", old); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-24 * time.Hour)
	for i := range scanHistoryMax + 5 {
		m := scanAt(base.Add(time.Duration(i) * time.Minute))
		m.Failed, m.Error = true, fmt.Sprint(i)
		if err := s.RecordScanFailure("m1", m); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.ScanHistory("m1")
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM fleet_scans WHERE machine_id = 'm1'`).Scan(&n)
	if n != scanHistoryMax || rows[0].Error != fmt.Sprint(scanHistoryMax+4) {
		t.Fatalf("kept %d rows (newest %q), want the newest %d", n, rows[0].Error, scanHistoryMax)
	}
}

// A report without its findings list is refused; one older than the newest stored scan is
// history only, never moving the findings backwards.
func TestScanReportGuards(t *testing.T) {
	s := newTestService(t)
	if _, _, err := decodeCVEReport(strings.NewReader(`{"scanned_at":"2026-01-01T00:00:00Z","trigger":"manual"}`), 10); err != nil {
		t.Fatal(err)
	}
	meta, _, _ := decodeCVEReport(strings.NewReader(`{"scanned_at":"2026-01-01T00:00:00Z"}`), 10)
	if meta.HasFindings {
		t.Fatal("a report without findings marked as having them")
	}
	if meta, _, _ := decodeCVEReport(strings.NewReader(`{"scanned_at":"2026-01-01T00:00:00Z","findings":null}`), 10); !meta.HasFindings {
		t.Fatal("a clean scan (findings: null) not recognised")
	}

	t0 := time.Now().Add(-time.Hour)
	if err := s.IngestCVEs("m1", scanAt(t0), []CVE{cve("CVE-NEW", "HIGH", "")}); err != nil {
		t.Fatal(err)
	}
	if err := s.IngestCVEs("m1", scanAt(t0.Add(-time.Hour)), []CVE{cve("CVE-OLD", "LOW", "")}); err != nil {
		t.Fatal(err)
	}
	var id string
	_ = s.db.QueryRow(`SELECT cve_id FROM fleet_cves WHERE machine_id = 'm1'`).Scan(&id)
	rows, _ := s.ScanHistory("m1")
	if id != "CVE-NEW" || len(rows) != 2 {
		t.Fatalf("findings %q after a late older scan, %d history rows", id, len(rows))
	}
}
