package logs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"api/internal/database"
)

// The stats endpoint: a no-type request returns every type keyed by type (the overview's
// single call), a typed request returns one StatsResponse, and a bogus type is a 400.
func TestGetStatsShapes(t *testing.T) {
	db, err := database.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Construct directly: New() hard-requires watcher env config we don't need here, and
	// handleGetStats only touches s.db.
	svc := &Service{db: db}

	ins := func(typ, ip, status string, bytes, cached int) {
		if _, err := db.Exec(`INSERT INTO logs (logs_timestamp, logs_type, logs_src_ip, logs_status, logs_bytes, logs_cached)
			VALUES (datetime('now'), ?, ?, ?, ?, ?)`, typ, ip, status, bytes, cached); err != nil {
			t.Fatal(err)
		}
	}
	ins("inbound", "10.0.0.1", "200", 100, 0)
	ins("inbound", "10.0.0.2", "200", 200, 0)
	ins("dns", "10.0.0.1", "NOERROR", 0, 1)
	ins("dns", "10.0.0.1", "BLOCKED", 0, 0)
	ins("outbound", "10.0.0.3", "", 500, 0)
	ins("fw", "9.9.9.9", "", 0, 0)

	get := func(q string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		svc.handleGetStats(rec, httptest.NewRequest("GET", "/api/logs/stats?"+q, nil))
		return rec
	}

	// No type → map keyed by type; each carries its own stats.
	rec := get("period=day")
	if rec.Code != 200 {
		t.Fatalf("no-type status = %d, want 200", rec.Code)
	}
	var m map[string]StatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("no-type body is not a per-type map: %v", err)
	}
	for _, k := range []string{"inbound", "dns", "outbound", "fw"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("no-type map missing key %q", k)
		}
	}
	if m["inbound"].TotalCount != 2 {
		t.Errorf("inbound total = %d, want 2", m["inbound"].TotalCount)
	}
	if m["dns"].BlockedCount != 1 {
		t.Errorf("dns blocked = %d, want 1", m["dns"].BlockedCount)
	}
	if m["dns"].CachedCount != 1 {
		t.Errorf("dns cached = %d, want 1", m["dns"].CachedCount)
	}

	// Typed → a single StatsResponse (an object, not a per-type map).
	rec = get("type=dns&period=day")
	if rec.Code != 200 {
		t.Fatalf("typed status = %d, want 200", rec.Code)
	}
	var one StatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil {
		t.Fatalf("typed body is not a StatsResponse: %v", err)
	}
	if one.TotalCount != 2 {
		t.Errorf("dns total = %d, want 2", one.TotalCount)
	}

	// Bogus type → 400, no silent empty stats.
	if rec := get("type=bogus&period=day"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bogus type status = %d, want 400", rec.Code)
	}
}
