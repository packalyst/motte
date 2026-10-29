package helper

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieName(t *testing.T) {
	if got := SessionCookieName(true); got != "__Host-motte_session" {
		t.Fatalf("secure name = %q, want __Host-motte_session", got)
	}
	if got := SessionCookieName(false); got != "motte_session" {
		t.Fatalf("insecure name = %q, want motte_session", got)
	}
}

func TestSessionTokenCookiePrecedenceOverBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "motte_session", Value: "cookie-tok"})
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
	if c.Name != "__Host-motte_session" {
		t.Errorf("name = %q, want __Host-motte_session", c.Name)
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

// Over HTTPS only the __Host- cookie counts: a plain-name cookie (which a sibling subdomain can
// set for the parent domain) is ignored, so it can't sign a logged-out browser into another
// session. Over plain HTTP only the plain name exists.
func TestSessionCookieNameByScheme(t *testing.T) {
	req := func(https bool, cookies ...*http.Cookie) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if https {
			r.Header.Set("X-Forwarded-Proto", "https")
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		return r
	}
	plain := &http.Cookie{Name: "motte_session", Value: "planted"}
	host := &http.Cookie{Name: "__Host-motte_session", Value: "mine"}
	for _, c := range []struct {
		name string
		r    *http.Request
		want string
	}{
		{"https, plain only", req(true, plain), ""},
		{"https, both", req(true, plain, host), "mine"},
		{"https, __Host- only", req(true, host), "mine"},
		{"http, plain", req(false, plain), "planted"},
		{"http, __Host- only", req(false, host), ""},
	} {
		if got := SessionToken(c.r); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if HasSessionCookie(c.r) != (c.want != "") {
			t.Errorf("%s: HasSessionCookie disagrees", c.name)
		}
	}
}

// A WebSocket through Traefik over HTTPS carries X-Forwarded-Proto "wss": it is HTTPS too, so its
// __Host- session cookie counts (otherwise every live connection was refused).
func TestEffectiveHTTPSWebSocket(t *testing.T) {
	for proto, want := range map[string]bool{"https": true, "wss": true, "WSS": true, "http": false, "ws": false, "": false} {
		r := httptest.NewRequest(http.MethodGet, "/api/ws", nil)
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		if got := EffectiveHTTPS(r); got != want {
			t.Errorf("X-Forwarded-Proto %q: %v, want %v", proto, got, want)
		}
	}
	ws := httptest.NewRequest(http.MethodGet, "/api/fleet/console/events", nil)
	ws.Header.Set("X-Forwarded-Proto", "wss")
	ws.AddCookie(&http.Cookie{Name: "__Host-motte_session", Value: "mine"})
	if got := SessionToken(ws); got != "mine" {
		t.Fatalf("a secure WebSocket's session cookie was ignored: %q", got)
	}
}
