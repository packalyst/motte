package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// withSessionCookie adds the plain (non-HTTPS) session cookie so the request looks
// cookie-authenticated to the CSRF gate.
func withSessionCookie(r *http.Request) *http.Request {
	r.AddCookie(&http.Cookie{Name: "wgpanel_session", Value: "tok"})
	return r
}

func runCSRF(t *testing.T, req *http.Request) int {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	(&Router{}).csrfMiddleware(ok).ServeHTTP(rec, req)
	return rec.Code
}

func TestCSRFAllowsSafeMethodsCrossOrigin(t *testing.T) {
	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "http://panel.example/api/x", nil))
	req.Header.Set("Origin", "http://evil.example")
	if code := runCSRF(t, req); code != http.StatusOK {
		t.Fatalf("GET should pass regardless of origin, got %d", code)
	}
}

func TestCSRFAllowsSameOriginWrite(t *testing.T) {
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "http://panel.example/api/x", nil))
	req.Host = "panel.example"
	req.Header.Set("Origin", "http://panel.example")
	if code := runCSRF(t, req); code != http.StatusOK {
		t.Fatalf("same-origin cookie write should pass, got %d", code)
	}
}

func TestCSRFRefusesCrossOriginCookieWrite(t *testing.T) {
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "http://panel.example/api/x", nil))
	req.Host = "panel.example"
	req.Header.Set("Origin", "http://evil.example")
	if code := runCSRF(t, req); code != http.StatusForbidden {
		t.Fatalf("cross-origin cookie write must be refused, got %d", code)
	}
}

func TestCSRFRefusesMissingOriginCookieWrite(t *testing.T) {
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "http://panel.example/api/x", nil))
	req.Host = "panel.example"
	// No Origin and no Referer.
	if code := runCSRF(t, req); code != http.StatusForbidden {
		t.Fatalf("missing-origin cookie write must be refused, got %d", code)
	}
}

func TestCSRFExemptsBearerClient(t *testing.T) {
	// No session cookie (a Bearer/script client) → exempt even cross-origin.
	req := httptest.NewRequest(http.MethodPost, "http://panel.example/api/x", nil)
	req.Host = "panel.example"
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Authorization", "Bearer tok")
	if code := runCSRF(t, req); code != http.StatusOK {
		t.Fatalf("header-authenticated client must be exempt, got %d", code)
	}
}

func TestCSRFUsesForwardedHost(t *testing.T) {
	// Behind Traefik the browser host arrives in X-Forwarded-Host; Origin must match it.
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "http://internal/api/x", nil))
	req.Host = "internal"
	req.Header.Set("X-Forwarded-Host", "panel.example")
	req.Header.Set("Origin", "https://panel.example")
	if code := runCSRF(t, req); code != http.StatusOK {
		t.Fatalf("origin matching X-Forwarded-Host should pass, got %d", code)
	}
}
