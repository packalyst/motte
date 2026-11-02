package retention

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// traffic_usage is swept like the other tables: rows older than the window go, newer ones stay.
// Buckets are written as Go times, the way the conntrack source stores them.
func TestSweepTrafficUsage(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE traffic_usage (peer_ip TEXT, dest_ip TEXT, bucket DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Hour)
	for _, age := range []time.Duration{0, 24 * time.Hour, 89 * 24 * time.Hour, 91 * 24 * time.Hour, 400 * 24 * time.Hour} {
		if _, err := db.Exec(`INSERT INTO traffic_usage VALUES ('10.0.0.2', '192.0.2.10', ?)`, now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	Sweep(db, 90)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM traffic_usage`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("%d rows left, want the 3 inside 90 days", n)
	}
}
