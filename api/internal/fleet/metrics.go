package fleet

import (
	"encoding/json"
	"net/http"
	"time"

	"api/internal/router"
)

// Usage history. The agent reports live metrics every ~15s, but the machine row
// only keeps the LAST report. Here we fold each report's CPU/mem/disk/load into a
// per-machine 5-minute bucket (running average + peak), so the machine page can
// draw usage over time. Raw samples are never stored — a bucket is one row that
// accumulates ~20 folds via avg = (avg*n + new)/(n+1) and MAX for the peak.

const metricsBucketSec = 300 // 5-minute buckets

// reportMetrics is just the metrics slice of an agent report — the only part we
// roll into history.
type reportMetrics struct {
	Metrics struct {
		CPU  float64 `json:"cpu"`
		Mem  float64 `json:"mem"`
		Disk float64 `json:"disk"`
		Load float64 `json:"load1"`
	} `json:"metrics"`
}

// recordMetrics folds one report's live metrics into the machine's current 5-min
// bucket. Called on every ingest; one cheap upsert. Best-effort — history is not
// worth failing a report over, so errors are swallowed.
func (s *Service) recordMetrics(machineID string, body []byte) {
	var rm reportMetrics
	if err := json.Unmarshal(body, &rm); err != nil {
		return
	}
	mt := rm.Metrics
	bucket := time.Now().UTC().Unix() / metricsBucketSec * metricsBucketSec
	// The avg columns update as a running mean over `samples`; the max columns keep
	// the peak. On the RHS of DO UPDATE, the bare column names are the row's values
	// BEFORE this statement — so `samples` is the prior count, as the mean needs.
	_, _ = s.db.Exec(`
		INSERT INTO fleet_metrics (machine_id, bucket, cpu_avg, cpu_max, mem_avg, mem_max, disk_avg, disk_max, load_avg, load_max, samples)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(machine_id, bucket) DO UPDATE SET
			cpu_avg  = (cpu_avg  * samples + excluded.cpu_avg ) / (samples + 1),
			mem_avg  = (mem_avg  * samples + excluded.mem_avg ) / (samples + 1),
			disk_avg = (disk_avg * samples + excluded.disk_avg) / (samples + 1),
			load_avg = (load_avg * samples + excluded.load_avg) / (samples + 1),
			cpu_max  = MAX(cpu_max,  excluded.cpu_max),
			mem_max  = MAX(mem_max,  excluded.mem_max),
			disk_max = MAX(disk_max, excluded.disk_max),
			load_max = MAX(load_max, excluded.load_max),
			samples  = samples + 1`,
		machineID, bucket, mt.CPU, mt.CPU, mt.Mem, mt.Mem, mt.Disk, mt.Disk, mt.Load, mt.Load)
	// Pruning is handled centrally by the retention sweep (package retention), so the
	// window is one settings-driven value across all aggregate tables.
}

// metricPoint is one regrouped point of a machine's usage history.
type metricPoint struct {
	T       int64   `json:"t"` // unix seconds (coarse bucket start)
	CPUAvg  float64 `json:"cpu_avg"`
	CPUMax  float64 `json:"cpu_max"`
	MemAvg  float64 `json:"mem_avg"`
	MemMax  float64 `json:"mem_max"`
	DiskAvg float64 `json:"disk_avg"`
	DiskMax float64 `json:"disk_max"`
}

// metricRange maps a UI range to how far back to look and how coarsely to regroup
// the 5-min buckets, so any range returns ~250-300 points (a light chart payload).
var metricRanges = map[string]struct {
	span time.Duration
	step int64
}{
	"24h": {24 * time.Hour, 300},       // 288 pts (native 5-min buckets)
	"7d":  {7 * 24 * time.Hour, 1800},  // 30-min steps → 336 pts
	"30d": {30 * 24 * time.Hour, 7200}, // 2-hour steps → 360 pts
}

// handleMetricsHistory serves a machine's usage history.
// GET /api/fleet/metrics?id=<machine_id>&range=24h|7d|30d
func (s *Service) handleMetricsHistory(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		router.JSONError(w, "id required", http.StatusBadRequest)
		return
	}
	rc, ok := metricRanges[r.URL.Query().Get("range")]
	if !ok {
		rc = metricRanges["24h"]
	}
	since := time.Now().Add(-rc.span).Unix()
	rows, err := s.db.Query(`
		SELECT (bucket/?)*? AS b,
			AVG(cpu_avg),  MAX(cpu_max),
			AVG(mem_avg),  MAX(mem_max),
			AVG(disk_avg), MAX(disk_max)
		FROM fleet_metrics
		WHERE machine_id = ? AND bucket >= ?
		GROUP BY b ORDER BY b`, rc.step, rc.step, id, since)
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	pts := []metricPoint{}
	for rows.Next() {
		var p metricPoint
		if err := rows.Scan(&p.T, &p.CPUAvg, &p.CPUMax, &p.MemAvg, &p.MemMax, &p.DiskAvg, &p.DiskMax); err == nil {
			pts = append(pts, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": pts})
}
