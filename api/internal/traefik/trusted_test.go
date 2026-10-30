package traefik

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"api/internal/helper"
	"api/internal/router"
)

const trustedTestConfig = `http:
  middlewares:
    rate-limit:
      rateLimit:
        average: 100
        burst: 200
    rate-limit-strict:
      rateLimit:
        average: 10
        burst: 20
    sentinel_vpn:
      plugin:
        sentinel:
          ipFilter:
            sourceRange:
              - "10.8.0.0/16"
          errorMode: "403"
    sentinel_vpn_silent:
      plugin:
        sentinel:
          ipFilter:
            sourceRange:
              - "10.8.0.0/16"
          errorMode: "silent"
`

// Saving the allow-list keeps the locked VPN ranges even when the request drops them, persists
// only the extras, and writes locked + extras into both VPN-only middlewares. A restart's restore
// writes the same list back after manage.sh regenerated the file.
func TestTrustedNetworksSaveAndRestore(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("HEADSCALE_IP_RANGE", "100.64.0.0/16")
	t.Cleanup(func() { helper.SetTrustedExtras(nil); PersistTrustedNetworks = nil })
	var saved []string
	PersistTrustedNetworks = func(extras []string) error { saved = extras; return nil }

	path := filepath.Join(t.TempDir(), "core.yml")
	if err := os.WriteFile(path, []byte(trustedTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Service{configPath: path}
	const addExtra = `{"rateLimitAverage":100,"rateLimitBurst":200,"strictRateAverage":10,"strictRateBurst":20,"ipAllowlist":["198.51.100.7"]}`

	// A new trusted network needs step-up: refused, nothing is saved.
	router.SetStepUpFunc(func(w http.ResponseWriter, _ *http.Request) bool {
		w.WriteHeader(http.StatusPreconditionRequired)
		return false
	})
	t.Cleanup(func() { router.SetStepUpFunc(nil) })
	rr := httptest.NewRecorder()
	s.handleUpdateConfig(rr, httptest.NewRequest(http.MethodPut, "/api/traefik/config", strings.NewReader(addExtra)))
	if rr.Code != http.StatusPreconditionRequired || saved != nil {
		t.Fatalf("without step-up: %d, persisted %v", rr.Code, saved)
	}

	router.SetStepUpFunc(func(http.ResponseWriter, *http.Request) bool { return true })
	rr = httptest.NewRecorder()
	s.handleUpdateConfig(rr, httptest.NewRequest(http.MethodPut, "/api/traefik/config", strings.NewReader(addExtra)))
	if rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	want := []string{"10.8.0.0/16", "100.64.0.0/16", "198.51.100.7"}
	if !slices.Equal(saved, []string{"198.51.100.7"}) {
		t.Errorf("persisted %v, want only the extra", saved)
	}
	cfg := s.GetConfig()
	if !slices.Equal(cfg.IPAllowlist, want) || !slices.Equal(cfg.LockedRanges, want[:2]) {
		t.Fatalf("allow-list %v locked %v", cfg.IPAllowlist, cfg.LockedRanges)
	}
	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "198.51.100.7") != 2 {
		t.Errorf("both VPN-only middlewares must carry the list:\n%s", data)
	}

	// manage.sh regenerates the file with the VPN ranges only; the startup restore adds the extras back.
	if err := os.WriteFile(path, []byte(trustedTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	s.RestoreTrustedNetworks()
	if got := s.GetConfig().IPAllowlist; !slices.Equal(got, want) {
		t.Fatalf("after restore: %v, want %v", got, want)
	}

	// Saving the same list again (or the rate limits alone) adds nothing: no step-up asked.
	router.SetStepUpFunc(func(w http.ResponseWriter, _ *http.Request) bool {
		w.WriteHeader(http.StatusPreconditionRequired)
		return false
	})
	rr = httptest.NewRecorder()
	s.handleUpdateConfig(rr, httptest.NewRequest(http.MethodPut, "/api/traefik/config", strings.NewReader(addExtra)))
	if rr.Code != http.StatusOK {
		t.Fatalf("unchanged list: %d %s", rr.Code, rr.Body)
	}

	// A malformed or too-broad entry is refused and changes nothing.
	rr = httptest.NewRecorder()
	s.handleUpdateConfig(rr, httptest.NewRequest(http.MethodPut, "/api/traefik/config", strings.NewReader(`{"ipAllowlist":["0.0.0.0/1"]}`)))
	if rr.Code != http.StatusBadRequest || !slices.Equal(saved, []string{"198.51.100.7"}) {
		t.Fatalf("too-broad entry: %d, persisted %v", rr.Code, saved)
	}
}
