package events

import (
	"testing"

	"api/internal/database"
)

// setupDB returns the shared DB with an empty events table. The database package
// initializes its singleton once per process, so each test clears the table rather
// than relying on a fresh instance.
func setupDB(t *testing.T) *database.DB {
	t.Helper()
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, err := database.GetDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM events`); err != nil {
		t.Fatal(err)
	}
	return db
}

// Audit attributes an event to an actor and source IP; Log leaves both empty.
func TestAuditRecordsActorAndIP(t *testing.T) {
	setupDB(t)

	Log("firewall", "op", SeverityInfo, "routine op")
	Audit("auth", "login", SeverityInfo, "alice", "203.0.113.7", "login ok")

	list, err := List(100, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 events, got %d", len(list))
	}

	// List is newest-first, so the audit row is first.
	if a := list[0]; a.Actor != "alice" || a.IP != "203.0.113.7" {
		t.Fatalf("audit actor/ip = %q/%q, want alice/203.0.113.7", a.Actor, a.IP)
	}
	if op := list[1]; op.Actor != "" || op.IP != "" {
		t.Fatalf("operational row should have empty actor/ip, got %q/%q", op.Actor, op.IP)
	}
}

// trim evicts old operational rows but never the audit trail, even when the
// operational cutoff covers every current row.
func TestTrimKeepsAuditDropsOldOperational(t *testing.T) {
	db := setupDB(t)

	Log("sys", "op", SeverityInfo, "op1")
	Log("sys", "op", SeverityInfo, "op2")
	Log("sys", "op", SeverityInfo, "op3")
	Audit("auth", "login", SeverityWarning, "alice", "203.0.113.7", "login1")
	Audit("auth", "login", SeverityWarning, "bob", "203.0.113.8", "login2")

	// Drive the operational cutoff (latestID - maxRows) past the highest current id, so
	// every operational row is in range — only the actor-filter should spare the audit rows.
	var maxID int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM events`).Scan(&maxID); err != nil {
		t.Fatal(err)
	}
	trim(db, maxID+maxRows)

	list, err := List(100, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("after trim want 2 surviving (audit) rows, got %d", len(list))
	}
	for _, e := range list {
		if e.Actor == "" {
			t.Fatalf("an operational row survived the trim: %+v", e)
		}
	}
}
