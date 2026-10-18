package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// reqWithRole builds a request carrying a principal with the given role; role "" means no
// principal (a public route).
func reqWithRole(method, role string) *http.Request {
	r := httptest.NewRequest(method, "/api/x", nil)
	if role != "" {
		r = r.WithContext(context.WithValue(r.Context(), principalCtxKey{}, &Principal{Role: role}))
	}
	return r
}

func TestAuthorizeRole(t *testing.T) {
	rt := &Router{}
	check := func(method, role, minRole string, want bool) {
		t.Helper()
		rec := httptest.NewRecorder()
		got := rt.authorizeRole(rec, reqWithRole(method, role), minRole)
		if got != want {
			t.Errorf("authorizeRole(%s, role=%q, min=%q) = %v, want %v", method, role, minRole, got, want)
		}
		if !want && rec.Code != http.StatusForbidden {
			t.Errorf("denied request should be 403, got %d", rec.Code)
		}
	}

	// No principal → public route, always allowed.
	check(http.MethodPost, "", "owner", true)
	// Default policy: reads need viewer, writes need admin.
	check(http.MethodGet, "viewer", "", true)
	check(http.MethodPost, "viewer", "", false)
	check(http.MethodPost, "operator", "", false)
	check(http.MethodPost, "admin", "", true)
	// Explicit min_role.
	check(http.MethodPost, "operator", "operator", true)
	check(http.MethodPost, "viewer", "operator", false)
	check(http.MethodPost, "admin", "owner", false)
	check(http.MethodDelete, "owner", "owner", true)
	// Unknown role fails closed.
	check(http.MethodGet, "bogus", "viewer", false)
}
