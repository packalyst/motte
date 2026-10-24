package fleet

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startTestMigration puts svc in a migration from :7001 to :7002 for the given machines,
// without opening real listeners.
func startTestMigration(svc *Service, now time.Time, ids ...string) {
	svc.mu.Lock()
	svc.port, svc.oldPort = 7002, 7001
	svc.initMigrationLocked(ids, now)
	svc.mu.Unlock()
}

// reqOnPort is an agent request that arrived on the given local port.
func reqOnPort(port int) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/report", nil)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, addr))
}

// The old port closes only once every machine has really connected on the new one: receiving
// the command (an ack) is not enough.
func TestPortMigrationWaitsForReconnect(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	addMachine(t, svc, "m2", true)
	now := time.Now()
	startTestMigration(svc, now, "m1", "m2")

	svc.noteListenerPort("m1", reqOnPort(7001)) // still on the old port
	if svc.migrationStep(now) {
		t.Fatal("finished with no machine on the new port")
	}
	svc.noteListenerPort("m1", reqOnPort(7002))
	if svc.migrationStep(now) {
		t.Fatal("finished with m2 still on the old port")
	}
	svc.noteListenerPort("m2", reqOnPort(7002))
	if !svc.migrationStep(now) {
		t.Fatal("not finished with every machine on the new port")
	}
	if active, _ := svc.migrationState(); active {
		t.Fatal("still migrating after completion")
	}
}

// A machine that hasn't moved by the grace window keeps the old port open (up to the cap);
// a deleted machine isn't waited for.
func TestPortMigrationKeepsOldPortForStragglers(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	addMachine(t, svc, "gone", true)
	now := time.Now()
	startTestMigration(svc, now, "m1", "gone")
	if _, err := svc.db.Exec(`DELETE FROM fleet_machines WHERE id = 'gone'`); err != nil {
		t.Fatal(err)
	}

	if svc.migrationStep(now.Add(portMigrationGrace + time.Second)) {
		t.Fatal("closed the old port while m1 still needs it")
	}
	if _, endsAt := svc.migrationState(); !endsAt.Equal(now.Add(portMigrationMax)) {
		t.Fatalf("old port not kept open to the cap: %v", endsAt)
	}
	if svc.migrationStep(now.Add(time.Hour)) {
		t.Fatal("closed before the cap")
	}
	if !svc.migrationStep(now.Add(portMigrationMax + time.Second)) {
		t.Fatal("old port still open past the cap")
	}
}

// During a port change the listener can still be switched off (both ports close), and the old
// port can be closed early (with a step-up); any other change waits.
func TestPortMigrationConfigEscapes(t *testing.T) {
	post := func(svc *Service, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		svc.handleSetConfig(rr, asOwner(httptest.NewRequest(http.MethodPost, "/api/fleet/config", strings.NewReader(body))))
		return rr
	}
	svc := newTestService(t)
	if _, err := svc.db.Exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT, encrypted INTEGER DEFAULT 0, updated_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	addMachine(t, svc, "m1", true)
	startTestMigration(svc, time.Now(), "m1")
	if rr := post(svc, `{"enabled":true,"port":7003}`); rr.Code != http.StatusConflict {
		t.Fatalf("a new port mid-migration: %d, want 409", rr.Code)
	}
	// Closing the old port early can cut machines off: it takes a step-up.
	if rr := post(svc, `{"enabled":true,"port":7002,"finish_migration":true}`); rr.Code != http.StatusPreconditionRequired {
		t.Fatalf("finish now without step-up: %d, want 428", rr.Code)
	}
	if active, _ := svc.migrationState(); !active {
		t.Fatal("finished without a step-up")
	}
	svc.finishMigration("owner1", "")

	startTestMigration(svc, time.Now(), "m1")
	if rr := post(svc, `{"enabled":false,"port":7002}`); rr.Code != http.StatusOK {
		t.Fatalf("switching off mid-migration: %d %s", rr.Code, rr.Body.String())
	}
	if active, _ := svc.migrationState(); active {
		t.Fatal("still migrating after switching the listener off")
	}
}

// A machine still turning up on the old port is sent the new port again, at most every
// portMigrationResend.
func TestPortMigrationResendsToStragglers(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	startTestMigration(svc, time.Now().Add(-portMigrationResend-time.Minute), "m1")
	count := func() int {
		var n int
		_ = svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_commands WHERE machine_id = 'm1' AND type = 'set-panel-port'`).Scan(&n)
		return n
	}
	svc.noteListenerPort("m1", reqOnPort(7001))
	if n := count(); n != 1 {
		t.Fatalf("%d re-sends after the interval, want 1", n)
	}
	svc.noteListenerPort("m1", reqOnPort(7001))
	if n := count(); n != 1 {
		t.Fatalf("re-sent again within the interval (%d)", n)
	}
	if got := queuedPayload(t, svc, "m1", "set-panel-port"); got != `{"port":7002}` {
		t.Fatalf("re-sent %s, want the new port", got)
	}
}

// Ending a migration takes back the set-panel-port commands nobody picked up: a machine that comes
// back later must not move to a port that may be closed by then.
func TestPortMigrationEndCancelsPending(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	startTestMigration(svc, time.Now(), "m1")
	if _, err := svc.Enqueue("m1", "set-panel-port", []byte(`{"port":7002}`)); err != nil {
		t.Fatal(err)
	}
	svc.finishMigration("admin", "")
	var n int
	_ = svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_commands WHERE machine_id = 'm1' AND status = 'pending'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d set-panel-port still pending after the migration ended", n)
	}
}

// A machine whose record can't be read is still waited for: a database error never closes the
// old port on it.
func TestPortMigrationReadErrorKeepsWaiting(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	startTestMigration(svc, time.Now().Add(-portMigrationMax-time.Hour), "m1")
	if _, err := svc.db.Exec(`ALTER TABLE fleet_machines RENAME TO fleet_machines_gone`); err != nil {
		t.Fatal(err)
	}
	got := svc.unmovedMachines()
	if len(got) != 1 || got[0].id != "m1" {
		t.Fatalf("unreadable machine dropped from the wait: %+v", got)
	}
}

// set-panel-port is the panel's own message: no person sends it, not even the owner.
func TestSetPanelPortNotUserIssuable(t *testing.T) {
	rr := httptest.NewRecorder()
	if gatePanelInternalCommand(rr, asOwner(httptest.NewRequest(http.MethodPost, "/", nil)), "set-panel-port") || rr.Code != http.StatusForbidden {
		t.Fatalf("owner could queue set-panel-port (status %d)", rr.Code)
	}
}
