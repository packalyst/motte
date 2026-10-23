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

	list, err := List(Query{})
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

	list, err := List(Query{})
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

// Filters and the "load older" cursor are applied in SQL; search treats % and _ literally.
func TestListFiltersAndCursor(t *testing.T) {
	setupDB(t)
	Log("firewall", "op", SeverityInfo, "routine op")
	Audit("auth", "login", SeverityWarning, "alice", "203.0.113.7", "login failed")
	Log("backup", "op", SeverityCritical, "backup at 50% failed")

	if l, _ := List(Query{Severity: SeverityWarning}); len(l) != 1 || l[0].Actor != "alice" {
		t.Fatalf("severity filter: %+v", l)
	}
	if l, _ := List(Query{Search: "203.0.113"}); len(l) != 1 || l[0].Subsystem != "auth" {
		t.Fatalf("search by IP: %+v", l)
	}
	if l, _ := List(Query{Search: "50%"}); len(l) != 1 || l[0].Subsystem != "backup" {
		t.Fatalf("a literal %% must match only itself: %+v", l)
	}
	if l, _ := List(Query{Search: "%"}); len(l) != 1 {
		t.Fatalf("%% is not a wildcard: %+v", l)
	}
	page1, _ := List(Query{Limit: 2})
	if len(page1) != 2 {
		t.Fatalf("want 2, got %d", len(page1))
	}
	page2, _ := List(Query{Limit: 2, Before: page1[1].ID})
	if len(page2) != 1 || page2[0].Subsystem != "firewall" {
		t.Fatalf("cursor page: %+v", page2)
	}
	src, err := Sources()
	if err != nil || len(src) != 3 {
		t.Fatalf("sources: %+v %v", src, err)
	}
}
