package auth

import (
	"errors"
	"sync"
	"testing"
)

// Break-glass: the panel always keeps an owner. Two owners demoting or deleting each other at the
// same moment leave exactly one; the last owner can't be demoted or deleted; others can.
func TestLastOwnerKept(t *testing.T) {
	svc := newTestService(t)
	// The database is shared: other tests' owners step aside so these two are the only ones.
	others := []int64{}
	rows, err := svc.db.Query(`SELECT id FROM users WHERE role = ?`, RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		others = append(others, id)
	}
	rows.Close()
	for _, id := range others {
		svc.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, RoleAdmin, id)
	}
	t.Cleanup(func() {
		for _, id := range others {
			svc.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, RoleOwner, id)
		}
	})
	owners := func() (n int) {
		svc.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, RoleOwner).Scan(&n)
		return
	}

	a, err := svc.CreateUser("last_owner_a", "StrongP@ss1", RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.CreateUser("last_owner_b", "StrongP@ss1", RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.db.Exec(`DELETE FROM users WHERE id IN (?, ?)`, a.ID, b.ID) })

	both := func(f func(id int64) error) (refused int) {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, id := range []int64{a.ID, b.ID} {
			wg.Add(1)
			go func() { defer wg.Done(); errs[i] = f(id) }()
		}
		wg.Wait()
		for _, err := range errs {
			if errors.Is(err, errLastOwner) {
				refused++
			} else if err != nil {
				t.Fatal(err)
			}
		}
		return refused
	}
	for i := 0; i < 50; i++ {
		if refused := both(func(id int64) error { return svc.setRole(id, RoleAdmin) }); refused != 1 || owners() != 1 {
			t.Fatalf("round %d: %d refused, %d owners left; want 1 and 1", i, refused, owners())
		}
		svc.db.Exec(`UPDATE users SET role = ? WHERE id IN (?, ?)`, RoleOwner, a.ID, b.ID)
	}
	if refused := both(svc.deleteUser); refused != 1 || owners() != 1 {
		t.Fatalf("delete: %d refused, %d owners left; want 1 and 1", refused, owners())
	}

	// The one left: staying owner is fine, demoting or deleting it isn't; a missing user is not found.
	var last int64
	svc.db.QueryRow(`SELECT id FROM users WHERE role = ?`, RoleOwner).Scan(&last)
	if err := svc.setRole(last, RoleOwner); err != nil {
		t.Fatalf("owner to owner: %v", err)
	}
	if err := svc.setRole(last, RoleViewer); !errors.Is(err, errLastOwner) {
		t.Fatalf("demote the last owner: %v", err)
	}
	if err := svc.deleteUser(last); !errors.Is(err, errLastOwner) {
		t.Fatalf("delete the last owner: %v", err)
	}
	if err := svc.setRole(-1, RoleViewer); err == nil || errors.Is(err, errLastOwner) {
		t.Fatalf("missing user: %v", err)
	}
}
