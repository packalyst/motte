package helper

import (
	"net/http"
	"strings"
	"time"
)

// sessionCookieBase is the session cookie name. Over HTTPS it gains the __Host- prefix.
const sessionCookieBase = "wgpanel_session"

// EffectiveHTTPS reports whether the browser reached the panel over HTTPS, accounting for a
// terminating reverse proxy (Traefik) that forwards plain HTTP internally. It trusts
// X-Forwarded-Proto because the panel always sits behind that proxy (see ADR-0007).
func EffectiveHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// SessionCookieName returns the session cookie name. When secure, it uses the __Host-
// prefix, which browsers enforce to be Secure + Path=/ + host-only (no Domain), so a
// sibling subdomain can neither read nor overwrite it (session-fixation hardening).
func SessionCookieName(secure bool) string {
	if secure {
		return "__Host-" + sessionCookieBase
	}
	return sessionCookieBase
}

// SetSessionCookie writes the session token as an HttpOnly cookie. SameSite=Strict stops the
// browser attaching it to any cross-site request (the primary CSRF defense); Secure and the
// __Host- prefix are applied whenever the connection is effectively HTTPS.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	secure := EffectiveHTTPS(r)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName(secure),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie expires the session cookie. It clears both the secure (__Host-) and the
// plain name so logout works regardless of how the request scheme is observed.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	secure := EffectiveHTTPS(r)
	for _, name := range []string{SessionCookieName(true), SessionCookieName(false)} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// sessionCookieValue returns the session token carried by either cookie name, or "".
func sessionCookieValue(r *http.Request) string {
	for _, name := range []string{SessionCookieName(true), SessionCookieName(false)} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// HasSessionCookie reports whether the request carries a session cookie — an ambient
// credential the browser attaches automatically. The router's CSRF origin check applies
// only to these; a request authenticated solely by an Authorization header is exempt.
func HasSessionCookie(r *http.Request) bool {
	return sessionCookieValue(r) != ""
}
