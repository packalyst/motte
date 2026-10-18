package auth

import (
	"testing"

	"api/internal/database"
)

func TestRoleLadder(t *testing.T) {
	if !RoleAtLeast(RoleOwner, RoleAdmin) || !RoleAtLeast(RoleAdmin, RoleOperator) || !RoleAtLeast(RoleOperator, RoleViewer) {
		t.Error("higher roles must satisfy lower requirements")
	}
	if RoleAtLeast(RoleOperator, RoleAdmin) || RoleAtLeast(RoleViewer, RoleOperator) {
		t.Error("lower roles must NOT satisfy higher requirements")
	}
	if RoleAtLeast("bogus", RoleViewer) || RoleAtLeast(RoleOwner, "bogus") {
		t.Error("unknown roles must fail closed")
	}
	if !ValidRole(RoleViewer) || ValidRole("superuser") {
		t.Error("ValidRole mismatch")
	}
	if !ValidScopeKind(ScopeTag) || ValidScopeKind("galaxy") {
		t.Error("ValidScopeKind mismatch")
	}
}

func TestCanAssignAndModify(t *testing.T) {
	s := &Service{}
	owner := &User{Role: RoleOwner}
	admin := &User{Role: RoleAdmin}

	// Only an owner can grant owner/admin.
	if err := s.canAssignRole(owner, RoleAdmin); err != nil {
		t.Errorf("owner should be able to assign admin: %v", err)
	}
	if s.canAssignRole(admin, RoleAdmin) == nil {
		t.Error("admin must NOT be able to assign admin")
	}
	if s.canAssignRole(admin, RoleOwner) == nil {
		t.Error("admin must NOT be able to assign owner")
	}
	if err := s.canAssignRole(admin, RoleOperator); err != nil {
		t.Errorf("admin should be able to assign operator: %v", err)
	}

	// An admin can only modify strictly-lower users; an owner can modify anyone.
	if s.canModifyUser(admin, &User{Role: RoleAdmin}) == nil {
		t.Error("admin must NOT be able to modify another admin")
	}
	if err := s.canModifyUser(admin, &User{Role: RoleOperator}); err != nil {
		t.Errorf("admin should be able to modify an operator: %v", err)
	}
	if err := s.canModifyUser(owner, &User{Role: RoleOwner}); err != nil {
		t.Errorf("owner should be able to modify another owner: %v", err)
	}
}

// TestOwnerCount backs the break-glass guard: it must count owners accurately so the handlers
// can refuse to drop the last one.
func TestOwnerCount(t *testing.T) {
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	svc, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser("owner1", "StrongP@ss1", RoleOwner); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.ownerCount(); n != 1 {
		t.Fatalf("ownerCount = %d, want 1", n)
	}
	if _, err := svc.CreateUser("viewer1", "StrongP@ss1", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.ownerCount(); n != 1 {
		t.Fatalf("ownerCount after adding a viewer = %d, want 1", n)
	}
	if _, err := svc.CreateUser("owner2", "StrongP@ss2", RoleOwner); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.ownerCount(); n != 2 {
		t.Fatalf("ownerCount = %d, want 2", n)
	}
}
