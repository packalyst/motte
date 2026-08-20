# Session token → HttpOnly cookie

Move the session token out of `localStorage` into an HttpOnly, Secure, SameSite cookie so a
future XSS can't read it.

- **Status:** Open
- **Priority:** Low — the XSS chain that made this exploitable was closed (toast output-
  escaping + enroll hostname sanitize), so this is now pure defense-in-depth.

## Context
The token is stored in `localStorage` (UI login/setup) and read back for the
`Authorization: Bearer` header. `localStorage` is JS-readable, so any XSS could exfiltrate it.

## Why it's not a quick fix
The app INTENTIONALLY uses header-based auth (not cookies) to avoid CSRF — confirmed correct
by the auth audit (`helper.ExtractBearerToken` reads only the Authorization header, never a
cookie). Moving to an HttpOnly+Secure+SameSite=Strict cookie makes the token unstealable by
JS, but cookies auto-attach → reintroduces CSRF, so it must come WITH CSRF protection
(SameSite=Strict covers most; state-changing routes may still want a CSRF token). Touches:
login flow, setup wizard, every API call's auth header, the WS first-message auth, and the
router auth middleware. Needs careful testing so logins/WS don't break.

## Plan
Issue the session as HttpOnly+Secure+SameSite=Strict cookie at login; have the API read the
token from that cookie server-side (keep header fallback during migration); add CSRF defense
for cookie-auth; drop localStorage usage in the UI.
