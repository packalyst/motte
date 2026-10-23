package fleet

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// report builds a minimal report body carrying just the metrics we roll into history.
func metricBody(cpu, mem, disk, load float64) []byte {
	b, _ := json.Marshal(map[string]any{
		"metrics": map[string]float64{"cpu": cpu, "mem": mem, "disk": disk, "load1": load},
	})
	return b
}

// Two reports in the same 5-min bucket should fold into one row: avg is the mean,
// max is the peak.
func TestRecordMetricsAveragesAndPeaks(t *testing.T) {
	svc := newTestService(t)
	svc.recordMetrics("m1", metricBody(20, 40, 60, 1.0))
	svc.recordMetrics("m1", metricBody(80, 60, 60, 3.0))

	var samples int
	var cpuAvg, cpuMax, memAvg, loadMax float64
	err := svc.db.QueryRow(
		`SELECT samples, cpu_avg, cpu_max, mem_avg, load_max FROM fleet_metrics WHERE machine_id='m1'`,
	).Scan(&samples, &cpuAvg, &cpuMax, &memAvg, &loadMax)
	if err != nil {
		t.Fatal(err)
	}
	if samples != 2 {
		t.Fatalf("samples = %d, want 2", samples)
	}
	if cpuAvg != 50 {
		t.Errorf("cpu_avg = %v, want 50 (mean of 20,80)", cpuAvg)
	}
	if cpuMax != 80 {
		t.Errorf("cpu_max = %v, want 80", cpuMax)
	}
	if memAvg != 50 {
		t.Errorf("mem_avg = %v, want 50 (mean of 40,60)", memAvg)
	}
	if loadMax != 3.0 {
		t.Errorf("load_max = %v, want 3.0", loadMax)
	}
}

// The history endpoint returns the machine's points, and only that machine's.
func TestMetricsHistoryEndpoint(t *testing.T) {
	svc := newTestService(t)
	svc.recordMetrics("m1", metricBody(10, 20, 30, 0.5))
	svc.recordMetrics("m2", metricBody(90, 90, 90, 9.0)) // other machine — must not leak

	req := asOwner(httptest.NewRequest("GET", "/api/fleet/metrics?id=m1&range=24h", nil))
	rec := httptest.NewRecorder()
	svc.handleMetricsHistory(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Points []metricPoint `json:"points"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Points) != 1 {
		t.Fatalf("points = %d, want 1", len(body.Points))
	}
	if body.Points[0].CPUAvg != 10 || body.Points[0].DiskAvg != 30 {
		t.Errorf("unexpected point %+v", body.Points[0])
	}
	if la := body.Points[0].LoadAvg; la == nil || *la != 0.5 {
		t.Errorf("load_avg = %v, want 0.5", la)
	}
}

// A bucket stored without load (older rows) still comes back, with load_avg null.
func TestMetricsHistoryNullLoad(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.db.Exec(`INSERT INTO fleet_metrics (machine_id, bucket, cpu_avg, cpu_max, mem_avg, mem_max, disk_avg, disk_max, samples)
		VALUES ('m1', ?, 10, 10, 20, 20, 30, 30, 1)`, time.Now().Unix()/300*300); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	svc.handleMetricsHistory(rec, asOwner(httptest.NewRequest("GET", "/api/fleet/metrics?id=m1", nil)))
	var body struct {
		Points []metricPoint `json:"points"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Points) != 1 || body.Points[0].LoadAvg != nil {
		t.Fatalf("want one point with null load, got %+v", body.Points)
	}
}

// An unknown range must fall back to the default window, and a missing id is a 400.
func TestMetricsHistoryValidation(t *testing.T) {
	svc := newTestService(t)
	rec := httptest.NewRecorder()
	svc.handleMetricsHistory(rec, httptest.NewRequest("GET", "/api/fleet/metrics", nil))
	if rec.Code != 400 {
		t.Fatalf("missing id: status = %d, want 400", rec.Code)
	}
	rec = httptest.NewRecorder()
	svc.handleMetricsHistory(rec, asOwner(httptest.NewRequest("GET", "/api/fleet/metrics?id=m1&range=bogus", nil)))
	if rec.Code != 200 {
		t.Fatalf("bogus range should fall back, got %d", rec.Code)
	}
}
