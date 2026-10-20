package fleet

import (
	"testing"
	"time"
)

func TestConsoleGrants(t *testing.T) {
	// Normal grant: single-use and bound to the minting user + machine.
	id := mintGrant(7, "m1", false, time.Minute, 1)
	if _, ok := takeGrant(id, "m2", 7); ok {
		t.Error("grant must not validate for a different machine")
	}
	if _, ok := takeGrant(id, "m1", 8); ok {
		t.Error("a non-readonly grant must be bound to the minting user")
	}
	if _, ok := takeGrant(id, "m1", 7); !ok {
		t.Error("valid grant should be accepted for its user+machine")
	}
	if _, ok := takeGrant(id, "m1", 7); ok {
		t.Error("a single-use grant must not be reusable")
	}

	// Read-only (share) grant: any user in scope, multiple uses.
	rid := mintGrant(7, "m1", true, time.Minute, 3)
	if g, ok := takeGrant(rid, "m1", 99); !ok || !g.readonly {
		t.Error("readonly grant should be usable by another user and marked readonly")
	}
	if _, ok := takeGrant(rid, "m1", 100); !ok {
		t.Error("readonly grant should allow multiple uses")
	}

	// Expired grant is rejected.
	eid := mintGrant(7, "m1", false, -time.Second, 1)
	if _, ok := takeGrant(eid, "m1", 7); ok {
		t.Error("expired grant must be rejected")
	}
}
