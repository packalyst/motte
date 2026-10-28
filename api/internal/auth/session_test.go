package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestChangePasswordStatus: a wrong current password or a refused new one is a 400 the page shows,
// never a 401 (which the UI treats as "session ended" and logs out).
func TestChangePasswordStatus(t *testing.T) {
	svc := newTestService(t)
	const pw = "StrongP@ss1"
	u, err := svc.CreateUser("change_pw", pw, RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { passwordLimiter.clear(u.ID) })
	sess, err := svc.createSession(*u, "192.0.2.12", "test")
	if err != nil {
		t.Fatal(err)
	}
	change := func(current, next string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password",
			strings.NewReader(fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, current, next)))
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		rec := httptest.NewRecorder()
		svc.handleChangePassword(rec, req)
		return rec
	}

	for _, c := range []struct{ name, current, next, want string }{
		{"wrong current password", "wrong", "N3wStrongP@ss", "incorrect"},
		{"same as the old one", pw, pw, "different"},
		{"too weak", pw, "short", "at least"},
	} {
		if rec := change(c.current, c.next); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: status %d %s, want 400 mentioning %q", c.name, rec.Code, rec.Body, c.want)
		}
	}
	if rec := change(pw, "N3wStrongP@ss"); rec.Code != http.StatusOK {
		t.Errorf("valid change: status %d %s, want 200", rec.Code, rec.Body)
	}
}
