package setup

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api/internal/auth"
	"api/internal/database"
	"api/internal/router"
)

// Once an admin exists, the setup endpoints take the router's session check: a missing or invalid
// session is refused, an idle-locked one too (423), and only admins pass.
func TestSetupAuthOnceAdminExists(t *testing.T) {
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	authSvc, err := auth.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authSvc.CreateUser("setup_owner", "StrongP@ss1", auth.RoleOwner); err != nil {
		t.Fatal(err)
	}
	principals := map[string]*router.Principal{
		"admin-token":  {UserID: 1, Role: auth.RoleAdmin},
		"locked-token": {UserID: 1, Role: auth.RoleAdmin, Locked: true},
		"viewer-token": {UserID: 2, Role: auth.RoleViewer},
	}
	router.SetAuthResolver(func(token string) (*router.Principal, bool) {
		p, ok := principals[token]
		return p, ok
	})
	t.Cleanup(func() { router.SetAuthResolver(nil) })

	s := &Service{auth: authSvc}
	for token, want := range map[string]int{
		"":             http.StatusUnauthorized,
		"bogus":        http.StatusUnauthorized,
		"locked-token": http.StatusLocked,
		"viewer-token": http.StatusForbidden,
		"admin-token":  0,
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/setup/test-headscale", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		passed := s.requireAuthIfAdminExists(rec, r)
		if want == 0 && !passed {
			t.Errorf("%q: refused (%d), want allowed", token, rec.Code)
		}
		if want != 0 && (passed || rec.Code != want) {
			t.Errorf("%q: passed=%v status %d, want %d", token, passed, rec.Code, want)
		}
	}
}
