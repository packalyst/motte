package settings

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
)

// Only the offered sign-in lengths and idle-lock minutes are saved: 0 or less would end every new sign-in at once (the
// owner's too), a huge one would let sign-ins last for ever. A refused value saves nothing.
func TestSessionTimeoutOnlyOfferedLengths(t *testing.T) {
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	s := New()
	put := func(body string) int {
		w := httptest.NewRecorder()
		s.handleUpdateSettings(w, httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body)))
		return w.Code
	}

	for _, bad := range []string{"0", "-1", "999999999", "2", "abc", ""} {
		if code := put(`{"session_timeout":"` + bad + `","idle_lock_minutes":5}`); code != http.StatusBadRequest {
			t.Errorf("session_timeout %q: got %d, want 400", bad, code)
		}
	}
	if v, _ := getSetting("idle_lock_minutes"); v != "" {
		t.Fatalf("a refused request saved idle_lock_minutes=%q", v)
	}
	if h := SessionTimeoutHours(); h != 24 {
		t.Fatalf("nothing saved: want the default 24, got %d", h)
	}

	for _, bad := range []string{"-5", "7", "1440", "999999"} {
		if code := put(`{"idle_lock_minutes":` + bad + `}`); code != http.StatusBadRequest {
			t.Errorf("idle_lock_minutes %s: got %d, want 400", bad, code)
		}
	}
	if code := put(`{"idle_lock_minutes":15}`); code != http.StatusOK || IdleLockMinutes() != 15 {
		t.Fatalf("15: got %d / %d", code, IdleLockMinutes())
	}
	if err := setSetting("idle_lock_minutes", "7"); err != nil {
		t.Fatal(err)
	}
	if m := IdleLockMinutes(); m != 0 {
		t.Fatalf("stored 7: want 0, got %d", m)
	}

	if code := put(`{"session_timeout":"168"}`); code != http.StatusOK {
		t.Fatalf("168: got %d, want 200", code)
	}
	if h := SessionTimeoutHours(); h != 168 {
		t.Fatalf("got %d, want 168", h)
	}

	// A bad value already in the database (saved before the check) falls back to the default.
	if err := setSetting("session_timeout", "0"); err != nil {
		t.Fatal(err)
	}
	if h := SessionTimeoutHours(); h != 24 {
		t.Fatalf("stored 0: want the default 24, got %d", h)
	}
}
