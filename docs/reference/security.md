# Security Model

How the panel protects secrets, authenticates humans and agents, and constrains
who can reach it. This is the *application* security model. The nftables firewall —
the L3 gate that decides which packets ever reach the app — lives in
[networking-firewall.md](networking-firewall.md); this doc only summarises the two
firewall toggles the app owns and cross-links there for the packet-level detail.

Related: [architecture.md](architecture.md) · [backend.md](backend.md) ·
[data-model.md](data-model.md) · [fleet-agent.md](fleet-agent.md) ·
[deployment.md](deployment.md) · [api-surface.md](api-surface.md)

---

## 1. Encryption at rest

Everything sensitive the panel stores in its SQLite DB is encrypted with
**AES-256-GCM**. One process-wide key, derived from a single environment secret.

### The key: `ENCRYPTION_SECRET`

- Lives in `.env` (mode `600`), injected into the `api` container's environment at
  container start. It is **never** written to the database. See
  [deployment.md](deployment.md) for where `.env` is generated.
- `helper.InitEncryption()` reads it at boot and **`log.Fatal`s if it is unset** —
  the process refuses to start without it (`api/internal/helper/crypto.go:39-50`).
  Called early in `main()` (`api/cmd/main.go:82`), before any service that touches
  encrypted data.

### Key derivation — `ParseKey` (`crypto.go:29-35`)

The **same rule everywhere** turns the secret string into a 32-byte key. This is a
hard invariant: the live process and the offline rotation tool must derive keys
identically, or re-encrypted data could not be read back.

- If the secret decodes as **exactly 32 bytes of hex** → used directly as the AES
  key. `weak = false`.
- Otherwise → **`SHA-256(rawString)`** used as the key. `weak = true`.

### The weak-key fallback (a deliberate footgun, flagged not fixed)

When the secret is not proper 32-byte hex, the SHA-256 fallback still produces a
usable key, but it is a single **unsalted** SHA-256 of whatever string was supplied
— far more brute-forceable than a real 256-bit random key. The code keeps this path
rather than rejecting the secret because **changing the derivation later would make
existing ciphertext undecryptable** (`crypto.go:18-22`, `45-49`).

Weakness is surfaced twice so an operator actually notices:
- A startup-log `WARNING` (`crypto.go:48`).
- An **Activity-feed event** `security / weak_encryption_secret` at
  `SeverityWarning`, logged once the DB is up (`api/cmd/main.go:83-88`), recommending
  rotation and warning that rotating invalidates existing encrypted secrets.

Recommended strong key: `openssl rand -hex 32`.

### Ciphertext format (`EncryptWith` / `DecryptWith`, `crypto.go:54-94`)

```
base64_std( nonce ‖ AES-256-GCM_ciphertext_with_tag )
```

- A **fresh random 12-byte GCM nonce** (`gcm.NonceSize()`) is generated per
  encryption from `crypto/rand` and **prepended** to the sealed output; the whole
  blob is then standard-base64 encoded.
- Decrypt splits the first `NonceSize()` bytes back off as the nonce.
  `len(data) < NonceSize()` → `"ciphertext too short"`.
- **No version byte / no key-id / no AAD.** The format is unversioned, so there is
  no in-band way to tell which key or scheme produced a blob — rotation relies on
  "try the old key, it either decrypts or it doesn't" (see §2). Worth knowing before
  ever changing the scheme: old ciphertext carries no marker to distinguish it.

### API surface

| Function | Key used | Notes |
|---|---|---|
| `Encrypt(pt)` / `Decrypt(ct)` | process key (`encryptionKey`) | Return `"encryption not initialized"` if `InitEncryption` never ran (`crypto.go:96-110`). The everyday path. |
| `EncryptWith(key, pt)` / `DecryptWith(key, ct)` | explicit key arg | Let the rekey tool hold *two* keys at once (old + new). |

### What is encrypted

Every column/row listed in the rekey inventory (§2) — VPN client private &
preshared keys, TOTP secrets, the fleet CA private key, push-subscription keys, the
ephemeral VPN-router authkey, and all `settings` rows flagged `encrypted=1`. Encrypted
settings go through `setSettingEncrypted` / `getSettingEncrypted`
(`api/internal/settings/settings.go:532-569`), which set/honour the `encrypted=1`
flag and call `helper.Encrypt`/`Decrypt`. See [data-model.md](data-model.md) for the
schema.

Note on *hashes vs encryption*: user passwords are **bcrypt-hashed**, not encrypted,
and session tokens are **SHA-256-hashed** (§3) — those are one-way and are not part of
the encryption/rekey story.

---

## 2. Key rotation (rekey)

Rotating `ENCRYPTION_SECRET` means decrypting every at-rest secret with the old key
and re-encrypting it under the new one. Package `api/internal/rekey`
(`rekey.go`) does the DB work; `api/cmd/rekey_cmd.go` exposes it as one-shot
subcommands; `manage.sh rotate_key` orchestrates the whole safe procedure.

### Safety invariants (state these plainly)

1. **Runs with the api stopped** → the rekey process has exclusive DB access; nothing
   writes concurrently (`rekey.go:2-4`, `rekey_cmd.go:16-18`).
2. **Pre-flight decrypt-all before any write.** `scan()` decrypts *every* secret with
   the old key first. Any **critical** value that fails to decrypt aborts the whole
   run — *"better to change nothing than to swap the key and leave rows that can never
   be decrypted again"* (`rekey.go:5-8`, `65-97`).
3. **One atomic transaction.** All re-encrypted rows are written inside a single
   `db.Begin()` … `Commit()`. Any error → `Rollback()` and the DB is byte-for-byte
   unchanged (`rekey.go:139-172`).
4. **Refuse to rotate *to* a weak key.** `runRekey` calls `ParseKey(newHex)` and
   exits non-zero if `weak` — the new secret must be 32-byte hex
   (`rekey_cmd.go:69-73`).
5. **Swap the key only after `--rekey` exits 0, then verify.** The orchestrator swaps
   `.env` only on success and then runs `--rekey-check` (decrypt-all under the *new*
   key) before declaring victory; a failed verify triggers rollback.

### The encrypted-store inventory (`rekey.go:34-42`)

`columns` is the **complete** list of encrypted columns, deliberately including
`users_push_subscriptions` (which the *backup* package's list omits — noted in a
comment so the two lists don't silently drift):

| table | column | critical? |
|---|---|---|
| `vpn_clients` | `private_key_enc` | yes |
| `vpn_clients` | `preshared_key_enc` | yes |
| `users` | `totp_secret_enc` | yes |
| `fleet_ca` | `key_enc` | yes |
| `users_push_subscriptions` | `key_p256dh` | yes |
| `users_push_subscriptions` | `key_auth` | yes |
| `vpn_router_config` | `authkey_enc` | **no** — ephemeral, write-only, never read at runtime; a decrypt failure is *skipped* (counted as `Skipped`), not aborted |

Plus every `settings` row with `encrypted=1` (`rekey.go:109-134`). `tableExists`
guards each table so an install missing an optional table is skipped, not errored.
Table/column names are fixed literals (never user input), so building the SQL strings
with them is safe (`rekey.go:30-33`).

### One-shot subcommands (`rekey_cmd.go`)

Handled by `maybeRunRekey()` before the servers start, so they exit without booting
the app; a **non-zero exit means the DB was left unchanged**.

- **`api --rekey`** — reads `ENCRYPTION_SECRET` (old) *and* `ENCRYPTION_SECRET_NEW`
  (new); both required. Refuses a weak new key. Runs `rekey.Run(db, oldKey, newKey)`.
  Prints a per-category re-encrypt report.
- **`api --rekey-check`** — reads `ENCRYPTION_SECRET` only; runs `rekey.Check` (a
  read-only decrypt-all) and prints `N secrets decrypt OK`. Used both as a standalone
  audit and as the post-swap verification step.

### `manage.sh rotate_key` orchestration (`manage.sh:726-813`)

Re-execs as root, then a 7-step flow with a full backup and automatic rollback:

1. Read current `ENCRYPTION_SECRET` from `.env`; generate `new=$(openssl rand -hex 32)`.
2. **Stop `api`** (`docker compose stop api`) for exclusive DB access.
3. **Back up** `app.db*` into `backups/rekey-<ts>/` (mode `700`) **and** save the old
   key to `old-key.txt` (mode `600`). If backup fails → restart api, nothing changed.
4. **Pre-flight + atomic re-encrypt**: `docker compose run … -e ENCRYPTION_SECRET=$old
   -e ENCRYPTION_SECRET_NEW=$new … api --rekey`. On failure → DB unchanged, key **not**
   swapped, backup kept, api restarted, exit 1.
5. **Swap the key in `.env`** (`update_env_value`), re-chmod `.env` to `600`.
6. Restart the stack.
7. **Verify**: `… -e ENCRYPTION_SECRET=$new … api --rekey-check`. **On failure →
   automatic rollback**: stop api, restore `app.db*` from the backup, revert
   `ENCRYPTION_SECRET` to the old value, restart. Backup is kept.

On success it offers to delete the backup (which contains the *old* key) and warns to
delete it once confident if kept.

> Gotcha: the backup directory holds the old plaintext key. Treat `backups/rekey-*`
> as sensitive and delete it after a confirmed rotation.

---

## 3. Human authentication (login, sessions, 2FA)

Package `api/internal/auth`. There is one shared secret store: the **`users`** table
(`id`, `username`, `password_hash`, `totp_secret_enc`, `totp_enabled`, timestamps).
This is a single-admin-oriented panel (there's no self-serve signup — see
`CreateUser` below), but the machinery is multi-user-ready.

### Passwords

- **bcrypt** at `bcrypt.DefaultCost` (`auth.go:173`, `session.go:110`). Hash stored in
  `users.password_hash`; the plaintext is never persisted.
- Strength policy (`validatePassword`, `auth.go:126-159`): ≥ 8 chars **and** at least
  one upper, one lower, one digit, one special.
- **Timing-attack defence**: an unknown username still runs a dummy
  `bcrypt.CompareHashAndPassword` so login timing doesn't leak account existence
  (`auth.go:213-217`).

### Login flow (`Service.Login`, `auth.go:199-298`)

1. Normalise username (trim + lowercase), fetch the row.
2. bcrypt-verify the password → `ErrInvalidCredentials` on mismatch.
3. If `totp_enabled=1`: require a code (`ErrTOTPRequired` if absent), then
   **decrypt** `totp_secret_enc` with the process key, rate-limit, validate, and
   reject replays (§ 2FA below).
4. Generate a session and return the **raw** token to the client.

The HTTP wrapper `handleLogin` (`auth.go:391-429`) does per-client-IP rate limiting
*before* calling `Login`: `registerLoginAttempt` atomically checks lockout **and**
reserves a slot (closing the check-then-record race). A `ErrTOTPRequired` result
**refunds** the slot (correct password, 2FA still pending → not a failed attempt) and
returns `428 Precondition Required`; a genuine failure keeps the slot counted; success
clears attempts. Lockout: **5 attempts / 15-min window → 15-min lockout**
(`ratelimit.go:14`, `helper/constants.go:47-48`), with a `Retry-After` header.

### Sessions & tokens (`auth.go`, `session.go`)

- **Token = 32 bytes of `crypto/rand`, base64url** (`generateSessionID`,
  `auth.go:352-359`). That's 256 bits of entropy — the token itself is the bearer
  credential.
- **Only the SHA-256 hash of the token is stored** in `sessions.id`
  (`hashToken`, `auth.go:365-368`; INSERT at `auth.go:270-274`). Rationale in the code:
  a DB read (backup leak, injection elsewhere) yields **no usable tokens**. Plain
  SHA-256 (no salt/KDF) is appropriate here precisely because the token is already
  256 bits of random entropy, so no stretching is needed.
- Expiry = `now + session_timeout` hours (setting `session_timeout`, default **24**;
  `auth.go:267-268`).
- `ValidateSession` (`auth.go:301-328`) looks up `sessions` by **hashed** token with
  `expires_at > now`, joins `users`, and async-bumps `last_active` (throttled to once
  per minute). Everywhere a token is compared to a stored session id, it is the
  **hash** that is compared (e.g. "is this my current session?" in `GetSessions`,
  `RevokeSession`).
- Session management endpoints: list sessions, revoke one (**cannot revoke the current
  one** — use logout), revoke all others (`session.go`). Background cleanup of expired
  rows runs via `authSvc.Start()` (`cleanup.go`, wired at `main.go:103`).

### How a request is authenticated (`router.authMiddleware`, `router/router.go:261-330`)

The API router wraps all handlers. It is a **default-deny / fail-closed** gate:

- A small allowlist of **public** paths bypasses auth: prefixes `/api/setup/`,
  `/api/auth/login`, `/api/restart/` (own per-key secret), `/api/hook/` (own
  per-webhook keys); exact `/health`, `/api`, `/api/`, `/api/manifest.json`. `OPTIONS`
  (CORS preflight) passes.
- Everything else requires a token. **If the auth validator is nil** (auth disabled or
  failed to init at boot) the middleware returns `503` for protected paths rather than
  serving them unauthenticated — it fails closed. Public paths are matched first so a
  broken auth service can't lock you out of setup/login.
- Token is read **only** from the `Authorization: Bearer …` header, never a cookie
  (`helper.ExtractBearerToken`, `helper/helper.go:105-118`). Deliberate CSRF
  mitigation: browsers auto-attach cookies on cross-site requests, but not a Bearer
  header. The SPA sends the token from `localStorage` as a Bearer header; the WebSocket
  authenticates via its first message (`stores/websocket.js`), so there is no cookie
  auth path at all.

> Trade-off / known follow-up: the SPA keeps the token in `localStorage`
> (`ui/src/App.svelte`, `stores/app.js` — key `session_token`), which is readable by
> any script that achieves XSS. The CSP (§5) is the primary XSS backstop. Moving the
> token to an `HttpOnly` cookie is a tracked follow-up that would require adding CSRF
> protection — it is not done yet.

### Step-up re-authentication (a stolen token isn't enough for the dangerous ops)

Sensitive, persistence-granting actions require the caller's **current password**
again, on top of a valid session:

- **`CreateUser`** (`auth.go:455-494`): minting another admin login requires
  `currentPassword` (verified via `VerifyPassword`), and is audit-logged
  (`events.Log` `auth/user_created`, `SeverityWarning`). *(No UI wired yet; the
  endpoint stays hardened for future multi-admin.)*
- **`ChangePassword`** (`session.go:93-122`, handler `209-252`): verifies the current
  password first; on success **revokes every *other* session** for that user (a
  password change is often a compromise response — a stolen token elsewhere must not
  survive it) and audit-logs `auth/password_changed`.
- **`VerifyPassword`** (`session.go:81-90`) is the shared step-up primitive.

### 2FA / TOTP (`auth/totp.go`, verification in `auth.go`)

- Standard RFC-6238 TOTP via `github.com/pquerna/otp/totp`; issuer `"Wireguard"`
  (`helper.TOTPIssuer`, `constants.go:74`).
- **Setup** (`handleSetup2FA`): generates a secret, **encrypts** it into
  `users.totp_secret_enc` immediately but leaves `totp_enabled=0` until proven. Returns
  the secret and a QR code as a **`data:image/png;base64,…` URL** (see §5 — the CSP
  `img-src` deliberately allows `data:` so this inline QR renders).
- **Enable** (`handleEnable2FA`): decrypts the pending secret, validates the submitted
  code, then sets `totp_enabled=1`.
- **Disable** (`handleDisable2FA`): requires **both** the password and a valid current
  TOTP code, then clears `totp_secret_enc` and `totp_enabled`.
- **At login** (`auth.go:229-259`): decrypt secret → **rate-limit** (atomic
  reserve, 5 attempts / lockout, `registerTOTPAttempt`) → `totp.Validate` →
  **replay-reject** a code already consumed in its window (`totpReplayed` /
  `markTOTPUsed`, `ratelimit.go`) → clear attempts on success. The replay check closes
  the "same 6 digits reused within the 30-s window" gap that plain TOTP validation
  leaves open.

---

## 4. Fleet mTLS (agent ↔ panel)

The panel is a **private CA + enrollment service**; per-machine agents (`wgscout`)
join once with a one-time token, get a client cert, and thereafter speak **mutual
TLS**. Full agent lifecycle: [fleet-agent.md](fleet-agent.md). Package
`api/internal/fleet`.

### The private CA (`ca.go`)

- **P-256 ECDSA**, 10-year, `IsCA`, `MaxPathLenZero` (leaf-only issuance),
  usage `CertSign|CRLSign` (`generateCA`, `ca.go:58-102`).
- Generated on the panel on first use. The **cert is stored in the clear** (it's
  public) in `fleet_ca.cert_pem`; the **private key is AES-256-GCM-encrypted**
  (`helper.Encrypt`) into `fleet_ca.key_enc` and **never leaves the panel**
  (`ca.go:9-11`, `84-92`). This is why `fleet_ca.key_enc` is a *critical* rekey column
  (§2).
- `Fingerprint()` = `sha256:<hex>` of the CA cert DER — the value an agent **pins
  out-of-band** at install so it can verify the panel it's talking to (`ca.go:131-136`).

### Enrollment tokens (`tokens.go`) — one-time, hashed, short-lived

- Value = 32 bytes `crypto/rand`, base64url-raw. Returned **once** at creation
  (baked into the install command); **only its SHA-256 hash is persisted** in
  `fleet_tokens.token_hash` (`tokens.go:24-56`). Listing outstanding tokens returns
  **metadata only** — never the value or hash (`PendingToken`, `ListPendingTokens`).
- **`redeemToken`** is atomic and single-use: one `UPDATE … SET used=1 WHERE
  token_hash=? AND used=0 AND expires_at>now`; only one concurrent caller can get
  `RowsAffected()==1`, so a token can never be spent twice (`tokens.go:118-137`).

### Enroll → client cert (`enroll.go`)

`POST /enroll` is the **only** endpoint on the fleet listener that runs *without* a
client cert — the one-time token is the credential, over TLS the agent has verified by
the pinned CA fingerprint. Flow (`HandleEnroll`, `enroll.go:35-101`):

1. Body capped at 64 KiB (`http.MaxBytesReader`).
2. **Syntactic CSR check first, then redeem the token** — deliberately: redeem is a
   one-shot consume, so a malformed CSR mustn't burn the operator's token.
3. `SignClientCSR` (`ca.go:145-173`): parse the CSR, **verify the CSR's own
   signature**, use **only its public key**, and issue a short-lived
   (`clientCertTTL = 90 days`, `service.go:88`) client cert (`ExtKeyUsageClientAuth`)
   whose CN is a fresh panel-assigned machine id. **Agent private keys never transit**
   — the panel only ever sees the public half in the CSR.
4. Store the machine: sanitized display name, `machineIdentityHash`, cert fingerprint,
   WG pubkey.
5. Return the client cert + the CA cert (trust anchor the agent stores).

> **Hostname sanitisation (defence in depth).** The agent-supplied hostname is
> attacker-controlled and later rendered in the UI, so `sanitizeMachineName`
> (`enroll.go:107-122`) strips it to `[A-Za-z0-9 ._-]`, ≤ 64 chars — every
> `< > " '` and control byte an XSS payload needs is dropped **before it reaches the
> DB**, alongside output-escaping and the CSP.

### The mTLS listener & gating (`listener.go`, `mtls.go`, `service.go`)

- TLS config (`tlsConfig`, `listener.go:15-26`): server cert signed by the CA (so a
  CA-pinning agent can verify the panel), SANs = every non-loopback host IP + the SSL
  domain (valid whether the agent reaches the panel over WireGuard or the public
  address), `MinVersion` TLS 1.2, and **`ClientAuth: VerifyClientCertIfGiven`** —
  `/enroll` is reachable certless, but **any** cert presented must be CA-signed, so the
  report/command endpoints reject certless or foreign-cert connections at the TLS
  handshake, before any handler runs.
- The server cert is minted fresh at startup and held **in memory** — it is not
  persisted (`ServerCertificate`, `ca.go:175-214`).
- **`requireClientCert`** (`mtls.go:18-37`) gates every non-enroll endpoint with a
  two-part check that **both** must hold: (a) a client cert was presented, and (b) its
  fingerprint maps to an **enrolled, non-revoked** machine (`machineByCertFP`). A cert
  the CA signed but that no longer maps to a live machine (deleted/revoked host still
  running its old agent) is rejected and logged, so stale/rogue agents are visible.
- Endpoints (`Handler`, `listener.go:30-46`): `/enroll` (token), `/healthz` (open,
  returns CA fingerprint), and mTLS-gated `/report`, `/cve-report`, `/commands`,
  `/commands/ack`, `/deregister`. Listener binds `:port` over TLS (`service.go:149-162`).
- **The `/agent` install script is *not* served on this listener** — it goes out on the
  main api router via Traefik/443 (`fleetroute.go`, `HandleInstallScript`) so the
  download rides the panel's real cert and Traefik's rate-limit/blocklist middleware —
  "one guarded door". This mTLS listener is only the enroll/report/command channel.

> Not-yet-enforced: `machineIdentityHash` (SHA-256 of `/etc/machine-id | wg_pubkey`,
> captured at enroll) is provenance/re-enroll-detection and an *intended future*
> report-time replay second factor — it is **not consulted on report today**, so the
> live runtime binding is the client-cert fingerprint alone (`store.go:145-160`). Don't
> describe it as active replay protection.

---

## 5. Web hardening & secrets handling

### Content-Security-Policy (Traefik, `traefik/dynamic.yml.template:128-152`)

The CSP is the **primary XSS backstop** — the thing that neuters an injected script
even if one slips past input sanitisation and output-escaping. Set as a Traefik
`security-headers` middleware alongside `frameDeny`, `contentTypeNosniff`,
`browserXssFilter`, `referrerPolicy: strict-origin-when-cross-origin`, and HSTS
(`stsSeconds: 31536000`, inert over plain HTTP, active only once SSL is on).

```
default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none';
img-src 'self' data: https:;
style-src 'self' 'unsafe-inline' https://unpkg.com;
script-src 'self';
connect-src 'self' ws: wss: https://flagcdn.com https://unpkg.com https://*.tile.openstreetmap.org;
font-src 'self' data:
```

Key constraints and *why* (from the template's own comments):
- **`script-src 'self'`** — no inline scripts at all. The SPA carries none (the
  service-worker registration lives in `main.js`), so an injected `<script>` or inline
  handler is blocked. *If a bundled lib ever needs `eval`, `'unsafe-eval'` must be
  added here.*
- **`style-src` keeps `'unsafe-inline'`** — Svelte/Tailwind inject inline styles; that
  is not a script-exec vector. `unpkg.com` is allowed for the external Leaflet
  stylesheet.
- **`img-src … data: https:`** — `data:` is required so the **2FA QR code renders as a
  `data:image/png;base64` URL** (§3) and other inline images; `https:` covers Leaflet
  map tiles.
- **`connect-src`** must list every external host the app loads from, because the
  **service worker re-fetches every request via `fetch()`** — so even `<img>` tiles and
  flags become `connect-src`, not `img-src`. Hosts: `flagcdn.com` (country flags),
  `*.tile.openstreetmap.org` (map tiles), `unpkg.com` (Leaflet CSS + marker icons),
  plus same-origin `ws:`/`wss:` for the live WebSocket.
- `frame-ancestors 'none'` = the modern clickjacking guard (matches `frameDeny`).

### Secrets handling

- **AdGuard admin password bootstrap** (`api/cmd/bootstrap.go`,
  `main.go:280`). First-install chicken-and-egg: `manage.sh` writes the generated
  plaintext AdGuard password to `/adguard/.password.bootstrap` inside the shared bind
  mount. On first boot the panel **consumes** it — encrypts it into the `settings` DB
  as `adguard_password` (`SetSettingEncrypted`) — and **deletes the file** so no
  plaintext lingers on disk. Idempotent: a no-op if `adguard_password` is already set
  or the file is absent. The AdGuard side stores it **bcrypt-hashed** in its own YAML
  (`adguard/config.go:24-48`), so the plaintext exists only transiently in the panel's
  encrypted setting for re-pushing credentials.
- **Headscale API key** — stored encrypted as the `headscale_api_key` setting; the
  settings read-back API returns only a **boolean "is it set?"**, never the value
  (`settings.go:93,187-190`). Same pattern for `adguard_password` in the status
  response (`settings.go:97,197-200`).
- General rule in the settings API: sensitive values are **write-only from the
  client's view** — you can set them, but GET responses expose presence flags, not the
  secret.

---

## 6. Access controls: L3 vs L7

Two operator toggles decide *who can reach the panel at all*, at two layers. Both live
in the settings API (`api/internal/settings/settings.go:131-132`); the **nftables /
Traefik enforcement detail is in [networking-firewall.md](networking-firewall.md)** —
summarised here only for the security picture.

- **`api_direct_access`** (UI: *panel-access*, L3). `false` **closes the API port to
  the public internet** at the packet layer — the panel is then reachable only via the
  trusted paths (WireGuard, loopback/Traefik). Flipping it calls
  `settings.RequestFirewallApply()` so the `panel-access` nftables table takes effect
  live (`settings.go:28-31,131`).
- **`web_cloudflare_only`** (UI: *cf_only*, L3). `true` allows **only Cloudflare edge
  IPs** to reach ports 80/443, so the public web front door can't be hit by bypassing
  Cloudflare (`settings.go:132`). The trusted-CF-IP list is kept current by
  `helper.StartCloudflareIPUpdater` (`main.go:90-93`), which also governs when
  `CF-Connecting-IP` is trusted for real client-IP resolution.

There is also an **L7** block toggle: `GetTraefikFWBlock` (default **on**) makes the
firewall block-list enforce at the Traefik/sentinel layer too, so blocks apply to
Cloudflare-proxied traffic that already passed L3 (`settings.go:571+`). Detail and the
nftables tables (`panel-access`, the CF range set, block-list) all live in
[networking-firewall.md](networking-firewall.md) — *"the firewall is the gate."*

---

## Invariants cheat-sheet

- Process **won't start** without `ENCRYPTION_SECRET`.
- Same `ParseKey` derivation in the live process and the rekey tool — never diverge, or
  data becomes undecryptable.
- Ciphertext = `base64(nonce‖ct)`, **unversioned** — no in-band key/scheme marker.
- Rekey: stop api → decrypt-all-first → one atomic tx → swap key only on success →
  verify → auto-rollback. Refuses a weak new key. Backup dir holds the old key — treat
  as sensitive.
- Passwords **bcrypt**; session tokens & enrollment tokens stored only as **SHA-256
  hashes**; TOTP secrets & the fleet CA key stored **AES-256-GCM-encrypted**.
- Auth middleware **fails closed**; token accepted from **Bearer header only** (no
  cookie → CSRF-resistant).
- Sensitive account ops (create-user, change-password) need **step-up** current
  password and are **audit-logged**.
- Fleet: agent private keys never transit; tokens single-use & hashed; runtime trust =
  **CA-signed client cert mapped to an enrolled, non-revoked machine**.

---

## Unverified / flagged for the reader

- **Fleet listener port**: `service.go` binds `:<port>` where `port` is passed into
  `Start()`; I did not trace the exact default value or its env/settings source in
  `main.go` — confirm the concrete port in [deployment.md](deployment.md) /
  [fleet-agent.md](fleet-agent.md) before quoting a number.
- **Backup package's encrypted-column list**: `rekey.go` explicitly notes it differs
  from the backup package's list (backup omits `users_push_subscriptions`). I did not
  read the backup package here — if you touch either list, reconcile both so a rekey
  and a backup cover the same columns.
- The `HttpOnly`-cookie migration and the fleet `machineIdentityHash` report-time
  replay check are **designed-but-not-built** per the code comments; treat both as
  future work, not current guarantees.
</content>
</invoke>
