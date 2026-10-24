package fleet

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// startTestMigration puts svc in a migration from :7001 to :7002 for the given machines,
// without opening real listeners.
func startTestMigration(svc *Service, now time.Time, ids ...string) {
	svc.mu.Lock()
	svc.port, svc.oldPort = 7002, 7001
	svc.migrating = true
	svc.migrateStarted = now
	svc.migrateEndsAt = now.Add(portMigrationGrace)
	svc.migrateMachines, svc.migrateMoved, svc.migrateExtended = ids, map[string]bool{}, false
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
