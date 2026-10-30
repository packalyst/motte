package traefik

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"api/internal/router"
)

// Switching VPN-only off puts the panel on the open internet: it takes a step-up, and without one
// the gate stays. Switching it on, or between its two modes, asks for none.
func TestVPNOnlyOffNeedsStepUp(t *testing.T) {
	t.Setenv("SSL_DOMAIN", "")
	t.Setenv("ADMIN_DOMAIN", "") // no AdGuard rewrite sync from a test
	path := filepath.Join(t.TempDir(), "core.yml")
	if err := os.WriteFile(path, []byte(renderCore(t, false)), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Service{configPath: path}
	set := func(mode string) int {
		rr := httptest.NewRecorder()
		s.handleSetVPNOnly(rr, httptest.NewRequest(http.MethodPost, "/api/traefik/vpn-only", strings.NewReader(`{"mode":"`+mode+`"}`)))
		return rr.Code
	}
	router.SetStepUpFunc(func(w http.ResponseWriter, _ *http.Request) bool {
		w.WriteHeader(http.StatusPreconditionRequired)
		return false
	})
	t.Cleanup(func() { router.SetStepUpFunc(nil) })

	for _, mode := range []string{"403", "silent"} {
		if code := set(mode); code != http.StatusOK || s.GetVPNOnlyMode() != mode {
			t.Fatalf("%s: %d, mode %s", mode, code, s.GetVPNOnlyMode())
		}
	}
	if code := set("off"); code != http.StatusPreconditionRequired || s.GetVPNOnlyMode() != "silent" {
		t.Fatalf("off without step-up: %d, mode %s", code, s.GetVPNOnlyMode())
	}
	router.SetStepUpFunc(func(http.ResponseWriter, *http.Request) bool { return true })
	if code := set("off"); code != http.StatusOK || s.GetVPNOnlyMode() != "off" {
		t.Fatalf("off with step-up: %d, mode %s", code, s.GetVPNOnlyMode())
	}
}
