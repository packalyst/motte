# 0012 — Fleet hardening + capability roadmap

- **Status:** Proposed (2026-10-18)
- **Relates to:** [0004](0004-secrets-encrypted-at-rest-with-rekey.md),
  [0005](0005-backups-sealed-with-argon2id.md),
  [0006](0006-fleet-agent-mtls-and-signed-releases.md),
  [0007](0007-client-ip-trust-model.md)

## Context

We reviewed the panel's remote-administration, auth, and fleet-ops posture against what modern
self-hosted admin tooling offers, and found a set of gaps worth closing. The panel and its
`wgscout` agent are strong on their core job — WireGuard, the nftables firewall, DHCP-managed LANs,
and fleet security telemetry (CVE, FIM, metrics, posture) — but lack an interactive host console,
some auth hardening, and a few operational refinements.

### Design principles to preserve

These are load-bearing choices the roadmap must **not** regress:

- **Agent identity is a per-host mTLS client certificate** from the panel CA, revoked on uninstall
  (ADR-0006). Any new agent channel rides this same identity — never a shared bearer token.
- **The fleet command path is a strict allowlist, re-checked by the agent, and is never a shell.**
  New capabilities that need interactivity (the console, point 7) are added as a **separate,
  explicitly gated channel** and must not loosen the allowlist.
- **Secrets and backups are sealed with argon2id** (ADR-0004/0005); auth hardening should align
  password hashing with that same standard.

### Gaps we're closing

| Capability | Current state |
|---|---|
| Interactive browser terminal (resumable sessions, copy/paste, image) | none |
| Password hashing | bcrypt (want argon2id — memory-hard, stronger) |
| Session storage | token in `localStorage` (want HttpOnly cookie) |
| Signed-update hardening | base signature verify only (no anti-rollback / selftest / key rollover) |
| Enrollment token | single-use only (no max-uses / expiry / group) |
| Command confirm/block guardrail | none (allowlist is all-or-nothing) |
| Passkeys / WebAuthn | none |
| RBAC roles + scopes | admins have full access |
| Per-resource step-up 2FA + idle lock | none |
| OIDC / SSO (+ SCIM) | none (org-only need) |
| Audit log | partial, ad-hoc |
| Off-host encrypted backups | local only |
| Resource-threshold alerts → email/webhook | designed, unbuilt |
| Supply-chain deploy gates (digest-pin, signature verify, auto-rollback) | none |
| Run one action across N hosts | none |

## Decision

Adopt the **12-point roadmap** below. Build every item on our own foundations (Go backend,
Svelte 5 UI, mTLS agent, allowlist, argon2id-sealed secrets); where an idea is borrowed from other
tooling it is **reimplemented, never imported**, and the design principles above are kept intact.

Each point states **Now** (what we have) and **To do** (what to change / improve), with effort and
care. "Care: auth/signing" means a focused security review and tests before merge.

### Foundations — hardening we should do regardless (points 1–6)

**1. Session tokens → HttpOnly cookies (+ CSRF)**
- *Now:* session token in `localStorage`, read by JS (XSS-exposed).
- *To do:* issue the session as a `Secure; HttpOnly; SameSite=Lax` cookie; add a CSRF token for
  state-changing requests; stop the UI reading the token from JS. **Prerequisite for OIDC (11) and
  passkeys (8).**
- *Files:* api auth/session handlers + router middleware; `ui/src` api client. *Effort: Med · Care: auth.*

**2. Password hashing → argon2id**
- *Now:* bcrypt.
- *To do:* make **argon2id** (`golang.org/x/crypto/argon2`) the default; **migrate-on-login** —
  when a user logs in against a bcrypt hash, transparently re-hash to argon2id; keep bcrypt verify
  for not-yet-migrated hashes. Aligns password hashing with our backup seal (ADR-0005).
- *Files:* api user/auth. *Effort: Low · Care: auth.*

**3. First-class audit log**
- *Now:* partial, ad-hoc logging.
- *To do:* a dedicated `audit` table + helper (actor, action, target, ip, ts, result) written on
  auth events, command dispatch, console open/close, and firewall/scope changes; a read-only UI
  view with filters. Underpins points 6, 7, 9, 10.
- *Files:* new `api/internal/audit`, DB migration, new UI view. *Effort: Med.*

**4. Signed-update hardening** *(extends ADR-0006)*
- *Now:* agent verifies the Ed25519 signature before applying an update.
- *To do:* (a) **anti-rollback** — persist the running version, refuse a lower version even if
  validly signed; (b) **selftest-before-swap** — run `new-binary --selftest` and only replace the
  old binary on success; (c) **signing-key rollover** — trust an incoming key embedded alongside
  the outgoing one so keys rotate without reinstalling agents.
- *Files:* `agent/selfupdate.go`, `agent/signing.go`, release tooling. *Effort: Low-Med · Care: signing.*

**5. Enrollment tokens: max-uses + expiry + group**
- *Now:* single-use enroll token (`fleet/enroll.go`).
- *To do:* token row gains `max_uses`, `uses_count`, `expires_at`, optional `label`/`group`;
  validation decrements and enforces expiry; **single-use becomes `max_uses = 1`** (no behaviour
  lost). Keep the vague invalid/used/expired response we already give.
- *Files:* `fleet/enroll.go`, DB migration, enroll UI. *Effort: Low.*

**6. Command guardrail**
- *Now:* allowlist only — commands are allowed or not; no "are you sure?" layer.
- *To do:* a server-side rule table classifying a dispatched command as **allow / confirm / block**
  (ship a sensible default pattern set); "confirm" requires an explicit acknowledgement, "block" is
  refused — applied **before** any fan-out. The allowlist stays underneath as the hard gate.
- *Files:* `fleet/commands.go` + new guardrail unit. *Effort: Low.*

### New capabilities (points 7–12)

**7. Browser console — flagship (replaces an external SSH client)**
- *Now:* none; operators SSH in with an external client.
- *To do:* agent opens a **persistent outbound WebSocket** to the panel over its existing **mTLS
  identity** (nothing new listens on the host); spawns a **PTY running `tmux new -A -s
  wgpanel-<id>`** so sessions **detach/reattach** (survive refresh and network drops); panel relays
  frames; Svelte `ConsoleView` built on **xterm.js** (`addon-fit`, `addon-clipboard`,
  `addon-web-links`; `addon-image` for paste in a later phase). **Security:** per-host
  **console-enabled toggle (default OFF)**, **step-up (10) required to open**, full **audit (3)** +
  optional transcript. This is a **separate capability** — never routed through the command
  allowlist.
- *Files:* agent (new PTY + WS client), new `api/internal/console` relay, new UI `ConsoleView`,
  launch from `MachinesView`. *Effort: High · Care: HIGH (new interactive-shell path).*

**8. Passkeys / WebAuthn**
- *Now:* password + TOTP.
- *To do:* WebAuthn registration/login (`go-webauthn`), per-user stored credentials; usable as a
  **login method and as step-up (10)**. Depends on point 1.
- *Files:* new `api/internal/webauthn`, DB, UI ceremony. *Effort: High · Care: auth.*

**9. RBAC — roles + scopes**
- *Now:* every admin has full access.
- *To do:* roles (`owner`/`admin`/`operator`/`viewer`) + scope (`all` / `tag:<t>` / `host:<h>`), a
  bindings table, and enforcement middleware on handlers; keep a **break-glass owner**. Foundation
  for points 10 and 11.
- *Files:* new `api/internal/authz`, DB, UI "Users & roles". *Effort: High · Care: auth.*

**10. Per-resource step-up 2FA + idle lock**
- *Now:* none.
- *To do:* mark sensitive actions (open console, firewall apply, a flagged host) **step-up
  required** → re-prompt TOTP/passkey; **idle-lock** the session after N minutes. Depends on
  points 1, 8, 9.
- *Files:* auth middleware, UI. *Effort: Med · Care: auth.*

**11. OIDC / SSO (+ optional SCIM) — org-only**
- *Now:* none (local login only).
- *To do:* `api/internal/oidc` with `/login`, `/callback`, `/status` using `go-oidc` + `oauth2`:
  **RS256-only** id_token verification, `iss`/`aud`/`exp`/`nonce` checks, **state + PKCE** with a
  browser-bound state cookie; provision users as `source='sso'`; optional allowed-group gate;
  **keep the local break-glass admin**. SCIM only if an IdP needs auto-provisioning. We connect to
  an IdP the user runs — we do **not** bundle one. Depends on point 1; scales with point 9. **Low
  priority unless an org/IdP is actually in play.**
- *Files:* new `api/internal/oidc`, UI login button. *Effort: Med (no RBAC) · Care: HIGH (auth).*

**12. Operational hardening**
- *Now:* local-only backups; alerts exist but no threshold rules; no supply-chain verification on
  update; no multi-host actions.
- *To do (sub-items):*
  - (a) **Resource-threshold alerts** — evaluate ingested CPU/mem/disk against rules → alert via
    email/webhook; merge with the agreed **Webhooks** design. *(`fleet/metrics.go` + alerts.)*
  - (b) **Off-host encrypted backups** — add cloud/SFTP destinations to the sealed-backup
    subsystem; store destination creds via encrypted-secrets (ADR-0004). *(Med.)*
  - (c) **Supply-chain deploy gates** — pin images **by digest** + optional signature verify +
    **health-gated auto-rollback** in the update flow. *(`manage.sh` / update flow.)*
  - (d) **Run on N hosts (allowlist-only)** — fan out an *existing allowlisted* action to selected
    machines with a live results grid; gated behind guardrail (6) + step-up (10). **Never** an
    arbitrary shell. *(Med · Care: mass action.)*
- *Effort: Low-Med each · Care: Med.*

### Sequencing

- **Phase 0 — foundation:** 1 (cookies), 2 (argon2id), 3 (audit).
- **Phase 1 — quick wins:** 4 (update hardening), 5 (enroll tokens), 6 (guardrail).
- **Phase 2 — flagship:** 7 (console) — ships with a basic TOTP gate first; tightens once 10 lands.
- **Phase 3 — enterprise auth:** 8 (passkeys) → 9 (RBAC) → 10 (step-up) → 11 (OIDC/SCIM, only if needed).
- **Phase 4 — ops:** 12 (a–d).

## Consequences

- (+) A clear, dependency-ordered path to **enterprise-grade** auth and ops without discarding our
  foundations (mTLS identity, no-shell allowlist, argon2id secrets).
- (+) The flagship console reuses the existing mTLS channel and installer; it is the single biggest
  user-facing win and the direct replacement for an external SSH client.
- (−) Points 7–11 touch auth and the agent-signing/transport paths — each is **HIGH-care** and needs
  its own review, tests, and (where it changes a load-bearing choice) a follow-up ADR.
- (−) RBAC (9) is a large, cross-cutting surface; until it lands, SSO (11) grants full-admin and must
  be gated by an allowed-group.
- (−) This is a roadmap, not a commitment to build all of it; points are independently shippable and
  may be dropped (OIDC/SCIM in particular) if the need never arises.
