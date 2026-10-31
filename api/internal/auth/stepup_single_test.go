package auth

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"api/internal/helper"
	"api/internal/router"
)

// The step-up lives in one place: no package outside auth reads a password or a 2FA code of its
// own, or checks one. They embed StepUpCreds and call RequireStepUp (or router.StepUp), so every
// sensitive action gets the same checks, lockout, audit and 428 answer.
func TestStepUpHasOneSource(t *testing.T) {
	own := regexp.MustCompile(`json:"(currentPassword|totpCode)"|\.VerifyPassword\(|\.verifyStepUp\(`)
	for _, root := range []string{"..", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Dir(path) == filepath.Join("..", "auth") { // auth's own files: the one place
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(src), "\n") {
				if own.MatchString(line) {
					t.Errorf("%s:%d: a step-up of its own; embed auth.StepUpCreds and call auth.RequireStepUp", path, i+1)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// A request without any credentials (the UI's first try, before it asked) is only answered: it
// counts no wrong attempt, so cancelling the prompt can never lock the user out.
func TestStepUpWithoutCredentialsCountsNoAttempt(t *testing.T) {
	svc := newTestService(t)
	const pw = "StrongP@ss1"
	u, err := svc.CreateUser("stepup_empty", pw, RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { passwordLimiter.clear(u.ID) })
	r := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	for i := 0; i <= helper.PasswordMaxAttempts; i++ {
		rec := httptest.NewRecorder()
		if svc.RequireStepUp(rec, r, u.ID, StepUpCreds{}) || rec.Code != http.StatusPreconditionRequired {
			t.Fatalf("try %d without credentials: %d, want 428", i, rec.Code)
		}
	}
	if !svc.RequireStepUp(httptest.NewRecorder(), r, u.ID, StepUpCreds{CurrentPassword: pw}) {
		t.Fatal("the right password was refused after prompts without credentials")
	}
}

// With a grace window, a confirmed step-up covers that session's next requests without
// credentials; another session, and a step-up without the window, still need them.
func TestStepUpGraceWindow(t *testing.T) {
	svc := newTestService(t)
	const pw = "StrongP@ss1"
	u, err := svc.CreateUser("stepup_grace", pw, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { passwordLimiter.clear(u.ID) })
	g := WithGrace(NewGraceWindow(10, helper.ConsoleStepUpGrace, helper.ConsoleStepUpGraceMax))
	as := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/fleet/command", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{UserID: u.ID}))
	}
	step := func(r *http.Request, c StepUpCreds, opts ...StepUpOption) bool {
		return svc.RequireStepUp(httptest.NewRecorder(), r, u.ID, c, opts...)
	}
	if step(as("synthetic-a"), StepUpCreds{}, g) {
		t.Fatal("no window before a step-up")
	}
	if step(as("synthetic-a"), StepUpCreds{CurrentPassword: "wrong"}, g) {
		t.Fatal("a wrong password passed")
	}
	if step(as("synthetic-a"), StepUpCreds{}, g) {
		t.Fatal("a failed step-up opened the window")
	}
	if !step(as("synthetic-a"), StepUpCreds{CurrentPassword: pw}, g) {
		t.Fatal("the right password was refused")
	}
	if !step(as("synthetic-a"), StepUpCreds{}, g) {
		t.Fatal("the window should cover the same session")
	}
	if step(as("synthetic-b"), StepUpCreds{}, g) {
		t.Fatal("another session must not share the window")
	}
	if step(as("synthetic-a"), StepUpCreds{}) {
		t.Fatal("a step-up without the window option must ask again")
	}
}
