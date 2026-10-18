package helper

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieName(t *testing.T) {
	if got := SessionCookieName(true); got != "__Host-wgpanel_session" {
		t.Fatalf("secure name = %q, want __Host-wgpanel_session", got)
	}
	if got := SessionCookieName(false); got != "wgpanel_session" {
		t.Fatalf("insecure name = %q, want wgpanel_session", got)
	}
}

func TestSessionTokenCookiePrecedenceOverBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "wgpanel_session", Value: "cookie-tok"})
	req.Header.Set("Authorization", "Bearer header-tok")
	if got := SessionToken(req); got != "cookie-tok" {
		t.Fatalf("SessionToken = %q, want cookie-tok (cookie must win)", got)
	}
}

func TestSessionTokenBearerFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer header-tok")
	if got := SessionToken(req); got != "header-tok" {
		t.Fatalf("SessionToken = %q, want header-tok", got)
	}
	if HasSessionCookie(req) {
		t.Fatal("HasSessionCookie should be false with no cookie")
	}
}

func TestSessionTokenNone(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := SessionToken(req); got != "" {
		t.Fatalf("SessionToken = %q, want empty", got)
	}
}

func TestSetSessionCookieAttributes(t *testing.T) {
	// Over HTTPS (via X-Forwarded-Proto) the cookie must be __Host-, Secure, HttpOnly, Strict.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, req, "tok-123", time.Now().Add(time.Hour))

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "__Host-wgpanel_session" {
		t.Errorf("name = %q, want __Host-wgpanel_session", c.Name)
	}
	if !c.HttpOnly {
		t.Error("cookie must be HttpOnly")
	}
	if !c.Secure {
		t.Error("cookie must be Secure over HTTPS")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("cookie must be SameSite=Strict")
	}
	if c.Path != "/" {
		t.Errorf("path = %q, want /", c.Path)
	}
	if c.Value != "tok-123" {
		t.Errorf("value = %q, want tok-123", c.Value)
	}
}
