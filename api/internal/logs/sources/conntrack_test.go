package sources

import (
	"fmt"
	"testing"

	"api/internal/bounded"
	"api/internal/database"
	"api/internal/logs"
)

func flowLine(dport int, up, down int64) string {
	return fmt.Sprintf("tcp 6 src=10.8.0.2 dst=10.8.0.3 sport=40000 dport=%d packets=1 bytes=%d src=10.8.0.3 dst=10.8.0.2 sport=%d dport=40000 packets=1 bytes=%d",
		dport, up, dport, down)
}

// Polls add only the growth since the last one and the close settles the rest, so a flow counts
// its bytes exactly once. With the map full, a new flow isn't tracked while open and is counted
// in full, once, when it closes.
func TestConntrackCountsOnce(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.8.0.0/24")
	db, err := database.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := NewConntrackWatcher(db, logs.Config{})
	w.counted = bounded.New[string, flowBytes](1, bounded.Refuse)
	total := func(dport int) (up, down int64) {
		_ = db.QueryRow(`SELECT COALESCE(SUM(bytes_up), 0), COALESCE(SUM(bytes_down), 0) FROM traffic_usage WHERE dest_port = ?`, dport).Scan(&up, &down)
		return
	}

	w.processLine(flowLine(443, 100, 200), false)
	w.processLine(flowLine(443, 150, 260), false)
	if up, down := total(443); up != 150 || down != 260 {
		t.Fatalf("after two polls: %d/%d, want 150/260", up, down)
	}

	// The map is full with the 443 flow: the 8443 flow isn't counted while open...
	w.processLine(flowLine(8443, 1000, 2000), false)
	w.processLine(flowLine(8443, 1500, 2500), false)
	if up, down := total(8443); up != 0 || down != 0 {
		t.Fatalf("an untracked open flow was counted: %d/%d", up, down)
	}
	// ... and is counted once, in full, when it closes.
	w.processLine(flowLine(8443, 1600, 2600), true)
	if up, down := total(8443); up != 1600 || down != 2600 {
		t.Fatalf("untracked flow at close: %d/%d, want 1600/2600", up, down)
	}

	w.processLine(flowLine(443, 170, 270), true)
	if up, down := total(443); up != 170 || down != 270 {
		t.Fatalf("tracked flow at close: %d/%d, want 170/270", up, down)
	}
	if w.counted.Len() != 0 {
		t.Fatalf("%d flows left after both closed", w.counted.Len())
	}
}
