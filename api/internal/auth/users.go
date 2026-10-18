package auth

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"api/internal/database"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// User management (multi-admin RBAC). All these endpoints are admin+ at the route level; the
// finer rules — only an owner may touch owners/admins, and the last owner can never be removed
// or demoted (break-glass) — are enforced here. Role/scope changes and deletions are
// step-up-re-authenticated and audit-logged, like user creation.

// callerFromSession resolves the authenticated operator behind the request, or writes 401.
func (s *Service) callerFromSession(w http.ResponseWriter, r *http.Request) *User {
	u, err := s.ValidateSession(helper.SessionToken(r))
	if err != nil {
		router.JSONError(w, "Invalid or expired session", http.StatusUnauthorized)
		return nil
	}
	return u
}

// canAssignRole reports whether caller may grant the target role: only an owner may grant
// owner/admin, and nobody may grant a role above their own.
func (s *Service) canAssignRole(caller *User, role string) error {
	if (role == RoleOwner || role == RoleAdmin) && caller.Role != RoleOwner {
		return fmt.Errorf("only an owner can assign the %q role", role)
	}
	if !RoleAtLeast(caller.Role, role) {
		return fmt.Errorf("cannot assign a role above your own")
	}
	return nil
}

// canModifyUser reports whether caller may change/remove target: an owner may modify anyone;
// anyone else may modify only strictly-lower-ranked users (so an admin can't touch another
// admin or an owner, and can't modify themselves into or out of their tier).
func (s *Service) canModifyUser(caller, target *User) error {
	if caller.Role == RoleOwner {
		return nil
	}
	if !RoleAtLeast(caller.Role, target.Role) || caller.Role == target.Role {
		return fmt.Errorf("you cannot modify a user at or above your own role")
	}
	return nil
}

// getUser loads one user (without the password hash).
func (s *Service) getUser(id int64) (*User, error) {
	var u User
	var lastLogin sql.NullTime
	err := s.db.QueryRow(
		`SELECT id, username, created_at, last_login, role, scope_kind, scope_values FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.CreatedAt, &lastLogin, &u.Role, &u.ScopeKind, &u.ScopeValues)
	if err != nil {
		return nil, err
	}
	u.LastLogin = database.TimeFromNull(lastLogin, time.Time{})
	return &u, nil
}

// ownerCount returns how many owner accounts exist — the break-glass guard reads this before
// any demotion or deletion so the panel can never be left without an owner.
func (s *Service) ownerCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, RoleOwner).Scan(&n)
	return n, err
}

// handleListUsers (GET /api/auth/users) lists accounts with their roles and scopes.
func (s *Service) handleListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(
		`SELECT id, username, created_at, last_login, role, scope_kind, scope_values FROM users ORDER BY id`)
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		var lastLogin sql.NullTime
		if err := rows.Scan(&u.ID, &u.Username, &u.CreatedAt, &lastLogin, &u.Role, &u.ScopeKind, &u.ScopeValues); err != nil {
			continue
		}
		u.LastLogin = database.TimeFromNull(lastLogin, time.Time{})
		users = append(users, u)
	}
	router.JSON(w, map[string]any{"users": users})
}

// handleUpdateUserRole (POST /api/auth/users/role) changes a user's role. Step-up + break-glass.
func (s *Service) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	caller := s.callerFromSession(w, r)
	if caller == nil {
		return
	}
	var req struct {
		UserID          int64  `json:"user_id"`
		Role            string `json:"role"`
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if !s.stepUp(w, caller.ID, req.CurrentPassword, req.TotpCode) {
		return
	}
	if !ValidRole(req.Role) {
		router.JSONError(w, "invalid role", http.StatusBadRequest)
		return
	}
	target, err := s.getUser(req.UserID)
	if err != nil {
		router.JSONError(w, "user not found", http.StatusNotFound)
		return
	}
	// Must be allowed to touch the target's current tier AND to grant the new one.
	if err := s.canModifyUser(caller, target); err != nil {
		router.JSONError(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.canAssignRole(caller, req.Role); err != nil {
		router.JSONError(w, err.Error(), http.StatusForbidden)
		return
	}
	// Break-glass: never demote the last owner.
	if target.Role == RoleOwner && req.Role != RoleOwner {
		if n, _ := s.ownerCount(); n <= 1 {
			router.JSONError(w, "cannot demote the last owner", http.StatusConflict)
			return
		}
	}
	if _, err := s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, req.Role, target.ID); err != nil {
		router.JSONError(w, "update failed", http.StatusInternalServerError)
		return
	}
	events.Audit("auth", "user_role_changed", events.SeverityWarning, caller.Username, helper.GetClientIP(r),
		fmt.Sprintf("Role of %q changed %s -> %s by %q", target.Username, target.Role, req.Role, caller.Username))
	router.JSON(w, map[string]bool{"ok": true})
}

// handleUpdateUserScope (POST /api/auth/users/scope) sets which fleet machines a user may act
// on. Meaningful for operator/viewer; owner/admin are always unscoped. Step-up + break-glass.
func (s *Service) handleUpdateUserScope(w http.ResponseWriter, r *http.Request) {
	caller := s.callerFromSession(w, r)
	if caller == nil {
		return
	}
	var req struct {
		UserID          int64  `json:"user_id"`
		ScopeKind       string `json:"scope_kind"`
		ScopeValues     string `json:"scope_values"`
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if !s.stepUp(w, caller.ID, req.CurrentPassword, req.TotpCode) {
		return
	}
	if !ValidScopeKind(req.ScopeKind) {
		router.JSONError(w, "invalid scope kind", http.StatusBadRequest)
		return
	}
	target, err := s.getUser(req.UserID)
	if err != nil {
		router.JSONError(w, "user not found", http.StatusNotFound)
		return
	}
	if err := s.canModifyUser(caller, target); err != nil {
		router.JSONError(w, err.Error(), http.StatusForbidden)
		return
	}
	values := req.ScopeValues
	if req.ScopeKind == ScopeAll {
		values = "" // "all" carries no value list
	}
	if _, err := s.db.Exec(`UPDATE users SET scope_kind = ?, scope_values = ? WHERE id = ?`, req.ScopeKind, values, target.ID); err != nil {
		router.JSONError(w, "update failed", http.StatusInternalServerError)
		return
	}
	events.Audit("auth", "user_scope_changed", events.SeverityWarning, caller.Username, helper.GetClientIP(r),
		fmt.Sprintf("Scope of %q set to %s(%s) by %q", target.Username, req.ScopeKind, values, caller.Username))
	router.JSON(w, map[string]bool{"ok": true})
}

// handleDeleteUser (POST /api/auth/users/delete) removes an account. Step-up + break-glass.
func (s *Service) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	caller := s.callerFromSession(w, r)
	if caller == nil {
		return
	}
	var req struct {
		UserID          int64  `json:"user_id"`
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if !s.stepUp(w, caller.ID, req.CurrentPassword, req.TotpCode) {
		return
	}
	target, err := s.getUser(req.UserID)
	if err != nil {
		router.JSONError(w, "user not found", http.StatusNotFound)
		return
	}
	if err := s.canModifyUser(caller, target); err != nil {
		router.JSONError(w, err.Error(), http.StatusForbidden)
		return
	}
	if target.Role == RoleOwner {
		if n, _ := s.ownerCount(); n <= 1 {
			router.JSONError(w, "cannot delete the last owner", http.StatusConflict)
			return
		}
	}
	if _, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, target.ID); err != nil {
		router.JSONError(w, "delete failed", http.StatusInternalServerError)
		return
	}
	events.Audit("auth", "user_deleted", events.SeverityWarning, caller.Username, helper.GetClientIP(r),
		fmt.Sprintf("Panel user %q (role %s) deleted by %q", target.Username, target.Role, caller.Username))
	router.JSON(w, map[string]bool{"ok": true})
}
