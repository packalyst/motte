package setup

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api/internal/router"
)

// Setup routes are public in the router, so their step-up first finds the signed-in caller: the
// check runs as that user, and a request with no session never reaches it.
func TestSetupStepUpRunsAsCaller(t *testing.T) {
	router.SetAuthResolver(func(token string) (*router.Principal, bool) {
		if token == "admin-token" {
			return &router.Principal{UserID: 7, Role: "admin"}, true
		}
		return nil, false
	})
	var asUser int64
	router.SetStepUpFunc(func(w http.ResponseWriter, r *http.Request) bool {
		if p := router.CurrentUser(r); p != nil {
			asUser = p.UserID
		}
		w.WriteHeader(http.StatusPreconditionRequired)
		return false
	})
	t.Cleanup(func() { router.SetAuthResolver(nil); router.SetStepUpFunc(nil) })

	rec := httptest.NewRecorder()
	if stepUp(rec, httptest.NewRequest(http.MethodPost, "/api/setup/generate-apikey", nil)) || rec.Code != http.StatusUnauthorized || asUser != 0 {
		t.Fatalf("no session: %d, step-up ran as %d", rec.Code, asUser)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/setup/generate-apikey", nil)
	r.Header.Set("Authorization", "Bearer admin-token")
	rec = httptest.NewRecorder()
	if stepUp(rec, r) || rec.Code != http.StatusPreconditionRequired || asUser != 7 {
		t.Fatalf("signed in: %d, step-up ran as %d (want 428 as user 7)", rec.Code, asUser)
	}
}
