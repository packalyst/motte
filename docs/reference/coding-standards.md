# Coding Standards & Patterns

> Conventions a new contributor (human or agent) MUST follow, derived from the actual
> codebase. Every rule below is backed by a real example (`file:line`). Where the code is
> inconsistent, that is called out explicitly — don't cargo-cult the exceptions.

**Siblings:** [README](./README.md) · [architecture](./architecture.md) ·
[backend](./backend.md) · [api-surface](./api-surface.md) · [data-model](./data-model.md) ·
[security](./security.md) · [networking-firewall](./networking-firewall.md) ·
[frontend](./frontend.md) · [deployment](./deployment.md) · [fleet-agent](./fleet-agent.md) ·
[rebuild-from-scratch](./rebuild-from-scratch.md)

---

## 0. The one overriding principle: security-first, and comment the WHY

Two things distinguish this codebase from a generic Go+Svelte app, and both are
non-negotiable:

1. **It is a security appliance.** The firewall, the encryption-at-rest, and the VPN-only
   admin plane are the product. A "clean refactor" that weakens any invariant in
   [§3](#3-security-first-rules-the-non-negotiables) is a regression, not a cleanup.
2. **Comments explain WHY, not WHAT.** The code is dense with doc-comments that justify a
   decision, name the failure mode being defended against, and warn the next editor. This is
   a deliberate house style — match it. A subtle firewall rule or a fail-open branch with no
   rationale comment will not pass review.

Look at `api/internal/nftables/firewall.go:43-61` (`ValidateIPv4OrCIDR`) or
`api/internal/nftables/firewall.go:448-458` (the ICMP-ordering NOTE): every non-obvious line
says *why it must be that way and what breaks otherwise*. That is the bar.

---

## 1. Go conventions

### 1.1 Package layout — one concern per package

All backend code lives under `api/internal/<domain>/`. Each package owns exactly one concern
(`firewall`, `nftables`, `wireguard`, `rekey`, `backup`, `headscale`, `adguard`, `fleet`,
`ws`, `router`, `helper`, …). The `main` entrypoint is `api/cmd/main.go`; it does nothing but
wire packages together (see [§1.7](#17-startup-wiring-maincmd)).

- **Cross-cutting utilities go in `api/internal/helper`** — crypto, validation, env parsing,
  the Docker client, SSRF-safe HTTP, IP/scanner helpers. If two packages would copy the same
  helper, it belongs here instead (see [§4 DRY](#4-dry--no-dead-code)).
- **Shared primitives that many packages need** (the DB handle, time helpers) live in
  `api/internal/database` and are fetched via `database.GetDB()`.
- A package that emits nftables never talks to HTTP; a handler package never builds nft
  script text directly. Keep the layers from bleeding into each other.

### 1.2 The handler / store / service split

Backend domains follow a consistent three-role split. `wireguard` is the canonical example:

| Role | File | Responsibility |
|------|------|----------------|
| **Service** | `wireguard/wireguard.go` | owns dependencies, exposes `Handlers()` for the router |
| **HTTP handlers** | `wireguard/handlers.go` | decode → validate → call store/service → JSON |
| **Store** | `wireguard/peerstore.go` | DB persistence + in-memory cache, encryption of secrets |

Rules:

- **Handlers are thin.** A handler decodes the request, validates input, calls into the
  store/service, and writes a response. Business logic and SQL do **not** live in handlers.
  See `handleCreatePeer` (`wireguard/handlers.go:54`): validate name → generate keys → build
  peer → hand to store.
- **A service exposes `Handlers() router.ServiceHandlers`** (a `map[string]HandlerFunc`) that
  `main` registers by name (`main.go:104` onward). Handlers are looked up by string key from
  the config-driven router — the config file, not code, decides which endpoints exist.
- **Stores encapsulate persistence and caching.** `PeerStore`
  (`wireguard/peerstore.go:23`) embeds a `sync.RWMutex`, keeps a `map[string]*Peer` cache,
  and is the *only* place peer rows are read/written. Secrets are encrypted before they hit
  the DB (`encryptPeerKeys`, referenced at `peerstore.go:60`).

### 1.3 Error handling & wrapping

- **Wrap errors with `%w` and a context prefix** at each layer boundary so the final message
  reads as a trace. See `nftables/service.go:131` (`"table %s: %w"`), `:139` (`"build: %w"`),
  `:150-154` (`"apply: %w"`), and `rekey/rekey.go:80` (`"scan %s.%s: %w"`).
- **Fail loudly only where a bad state is unrecoverable.** `log.Fatal` is reserved for
  startup preconditions that make the process useless — a missing `ENCRYPTION_SECRET`
  (`helper/crypto.go:42`), a config that won't load (`main.go:63`), a DB that won't init
  (`main.go:78`). Never `log.Fatal` inside a request handler.
- **In loops over DB rows, log-and-continue rather than abort** when one row is malformed, so
  a single bad record can't take down the whole read: `firewall.go:250-253` skips a row that
  fails to scan and logs it. Contrast with `rekey`, where a *critical* decrypt failure MUST
  abort the whole run (`rekey/rekey.go:91-94`) — the choice depends on the blast radius.
- **HTTP errors go through `router.JSONError`** (`router/router.go:709`) with an explicit
  status code — never `http.Error` with a bare string, never a naked 500.

### 1.4 Naming

- Exported constructors are `New…` returning the concrete type: `NewFirewallTable`
  (`firewall.go:87`), `NewPanelAccessTable` (`panel_access.go:39`). A package with a single
  service uses plain `New()` (`nftables/service.go:25`).
- Validators are `Validate…` (bool or error) and sanitizers are `Sanitize…`:
  `ValidateIdentifier`, `ValidateIPv4OrCIDR`, `SanitizeElement`, `SanitizeComment`
  (`nftables/script.go`). Boolean predicates read as questions: `isValidPortElement`
  (`firewall.go:18`), `tableExists` (`rekey.go:60`).
- Encrypted DB columns carry an `_enc` suffix everywhere (`private_key_enc`,
  `totp_secret_enc`, `key_enc` — `rekey/rekey.go:34-42`). This suffix is load-bearing: the
  rekey inventory and backup filters key off it.

### 1.5 Comment density & style — the house style

- **Package doc-comments state the design and the safety model up front.** `rekey/rekey.go:1-12`
  opens with a 4-point "Safety model"; `agent/main.go:1-20` lays out the phased design.
  Write these for any non-trivial package.
- **Every security-relevant branch gets a WHY comment naming the failure mode.** Examples to
  emulate:
  - `firewall.go:121-123` — why an IPv6 value is skipped (it would "wedge the whole atomic
    table").
  - `panel_access.go:60-63` — the `FAIL OPEN` block spells out "we must NEVER risk locking
    the panel out of its own management plane."
  - `script.go:88-90` — why `auto-merge` must be pulled out of the flags slice.
  - `helper/safehttp.go:44-46` — why CGNAT/`0.0.0.0/8` are blocked beyond `IsPrivate()`.
- **Leave `NOTE:` / warnings for the next editor** when an ordering or a scope is subtle:
  `firewall.go:448` ("emitted AFTER the block drops … so a blocked IP can't even ping"),
  `firewall.go:456-458` ("revisit this if the host ever gains real public IPv6").
- Keep comments truthful to the code. If you change the behavior, update the WHY — a stale
  rationale comment is worse than none here.

### 1.6 Helper patterns, context & timeouts

- **Every outbound HTTP call has a timeout and a shared, pooled transport.** Docker calls go
  through `helper.NewDockerHTTPClient()` (default `DockerClientTimeout = 30s`,
  `docker_client.go:17`) which reuses one pooled `*http.Transport` built once via
  `sync.Once` (`docker_client.go:28-50`) — do not `http.Get` the Docker socket ad hoc.
- **Operator-supplied URLs MUST use `helper.SafeExternalHTTPClient`** (`safehttp.go:29`),
  which validates the *resolved* IP at dial time (DNS-rebinding-safe, covers redirect hops).
  Never fetch a remote blocklist / webhook target with a plain client.
- **Guard shared mutable state with a mutex and snapshot under the lock**, then do slow work
  outside it. `nftables/service.go:230-236` copies the tables map under `applyMutex` before
  running the slower existence checks. `GetService()` uses an `RWMutex` (`service.go:46-50`).
- **Debounce bursty work.** Firewall reapplies are coalesced with a 500ms
  `time.AfterFunc` timer (`service.go:16`, `:79-113`) so N rapid edits produce one atomic
  `nft` apply.
- Prefer small pure helpers that are independently testable: `keepIPv4CIDRs`
  (`firewall.go:34`), `validCIDROr` (`panel_access.go:143`), `splitCIDRs` (`cf_only.go:104`).

### 1.7 Startup wiring (`api/cmd/main.go`)

`main` is a deterministic, ordered boot — respect the order, it encodes dependencies:

1. One-shot subcommands short-circuit before servers start: `maybeRunRekey()` (`main.go:51`).
2. `stats.Init()` → load config → `database.Init()` (`main.go:56-78`).
3. **`helper.InitEncryption()` before any service that touches secrets** (`main.go:82`); a
   weak key is surfaced to the Activity feed, not just the log (`main.go:83-88`).
4. Services are registered by name via `r.RegisterService(...)` and gated by
   `config.IsServiceEnabled(...)` — **auth first** because others depend on it
   (`main.go:98-104`).
5. nftables tables are registered on the single service instance
   (`main.go:180-195`): VPN ACL, firewall, panel-access, cloudflare-only.

New services follow the same shape: `svc, err := X.New()` → `r.RegisterService("x",
svc.Handlers())`, wrapped in an enabled-check.

---

## 2. nftables / firewall code (its own sub-discipline)

The firewall builders emit **text** that is applied atomically with `nft -f`. A single bad
element deletes-and-fails the whole table, so this code has extra rules
(see [networking-firewall](./networking-firewall.md) for the runtime picture):

- **Every value that flows into a rule passes a boundary validator before emission.**
  IPs/CIDRs → `ValidateIPv4OrCIDR` (`firewall.go:124,138`), ports → `isValidPortElement`
  (`firewall.go:152`), provider ranges → `keepIPv4CIDRs` (`firewall.go:201-204`). The reason
  is spelled out at `script.go:43-48`: an invalid element wedges the atomic reload and, for
  `vpn_acl`, silently flips peer isolation from default-deny to default-allow.
- **Identifiers, families, set types, hooks, policies are regex-validated in the builder**
  and fall back to a safe literal if invalid (`script.go:11-19`, `BuildSet` `:78-85`,
  `BuildChain` `:141-153`, `TableHeader` `:171-179`). An invalid name becomes
  `"invalid_set"` / `"invalid_chain"`, never raw interpolation.
- **Sanitize set elements and rule text** to strip newlines/`;`/`{`/`}`/`#` that could break
  syntax or inject rules: `SanitizeElement` (`script.go:64-74`), `SanitizeComment`
  (`script.go:192-198`), and the per-rule strip in `BuildChain` (`script.go:161-162`).
- **Group many builder arguments into a named struct.** `buildScript` takes `scriptParams`
  (`firewall.go:350-363`) precisely so "argument-order mistakes [are] impossible in this
  security-critical builder." Don't add another positional string param.
- **Emit shared rule blocks from one function** so two chains can't drift:
  `allowAndSaddrDropRules()` (`firewall.go:376-389`) is used by both the input and forward
  chains.
- A dedicated concern = a dedicated, clearly-named table. `wgadmin_panel_access` and
  `wgadmin_cf_only` are separate tables, not rules bolted onto `wgadmin_firewall`, so
  `nft list ruleset` is self-documenting (`panel_access.go:13-31`).

---

## 3. Security-first rules (the non-negotiables)

These are invariants, not preferences. Breaking one is a security bug even if tests pass.

### 3.1 Firewall fails OPEN — never lock the operator out

The management plane must never be dropped by rules we can't fully trust. When a restricting
table can't safely determine its inputs, it emits an **empty table** (no filtering):

- `panel_access.go:60-66`: if direct access is allowed, or the port / trusted sources can't
  be determined, emit an empty shell. Comment: "we must NEVER risk locking the panel out of
  its own management plane."
- `cf_only.go:49-53`: same stance for the Cloudflare-only web toggle.
- Any read error on the enabling setting returns "don't restrict" (`panel_access.go:97-101`,
  `cf_only.go:92-100`).
- **`trustedPanelSources()` always includes loopback** and the Docker/WG/Headscale ranges
  with hardcoded fallbacks matching `.env.example`, so a garbled env var can't drop a trusted
  source (`panel_access.go:113-141`). This is pinned by a test
  (`panel_access_test.go:38-53`).
- The Traefik L7 block-list is fail-open too: "if the list can't be fetched, it blocks no
  one, so it can't lock you out" (`traefik/dynamic.yml.template:176`).

> Corollary: the WAN-detection branches fail *closed* for IPv6 leakage
> (`firewall.go:470-481`) but the *admin path* always fails open. Know which is which: leaks
> close, lockouts open.

### 3.2 Validate nftables before it can take effect

Every element is validated at build time ([§2](#2-nftables--firewall-code-its-own-sub-discipline)).
For end-to-end syntax checking, scripts can be dumped and linted with `nft -c` via the
`DUMP_NFT_DIR` test hook (`nftables/dump_for_lint_test.go:9-14`). When adding rule shapes,
extend that dump so CI can `nft -c` them.

### 3.3 Secrets encrypted at rest, one derivation, atomic rotation

- **AES-256-GCM, random nonce prepended, base64** — one implementation, `EncryptWith` /
  `DecryptWith` (`helper/crypto.go:52-94`). Everything else calls `Encrypt`/`Decrypt` which
  use the process key.
- **Key derivation lives in exactly one place**, `ParseKey` (`helper/crypto.go:29-35`): a
  32-byte hex string is the key; anything else is SHA-256'd and flagged `weak`. This is
  shared by the live process and the rotation tool so re-encrypted data reads back
  (comment at `crypto.go:24-28`). Never fork this rule.
- **Rotation is all-or-nothing.** `rekey.Run` (`rekey/rekey.go:142-172`) pre-flights a
  decrypt of *every* secret with the old key, then re-encrypts inside one transaction; any
  error rolls back. The `columns` inventory (`rekey.go:34-42`) is the complete list of
  encrypted columns — **when you add an encrypted column, add it here**, or rotation will
  leave it un-rotated. The orchestrating shell (`manage.sh:725` `rotate_key`) backs up the
  DB, stops the api, swaps the key only after exit 0, and rolls back on verify failure.

### 3.4 Input validation & sanitization at every trust boundary

- User-facing identifiers get a strict allowlist regex: peer names
  (`wireguard/handlers.go:26` — restricted because they land in a `Content-Disposition`
  filename), Docker container names (`docker_client.go:66-68` — disallows `/` so a name can't
  traverse to other API endpoints).
- Central validators in `helper/validation.go` (`ValidateIP`, `ValidatePort`,
  `ValidateDomain`, `ValidateCIDR`, `ValidateURL`, `SanitizeInternalServiceURL`,
  `ValidateBlocklistURL`, …) — reuse these; don't hand-roll a new domain/URL check.
- **All SQL uses parameterized queries.** The only place table/column names are interpolated
  is `rekey`, and the comment explicitly notes they are "fixed literals, never user input"
  (`rekey/rekey.go:31-33`).
- Request bodies decode through `router.DecodeJSONOrError` (`router/router.go:759`), which
  returns a 400 on malformed JSON; there is a body-size-limit middleware
  (`router/router.go:250`).

### 3.5 VPN-only admin plane & the CSP backstop

- **Auth fails closed for protected paths.** A nil `authValidator` (auth disabled/failed to
  init) returns 503 rather than serving unauthenticated (`router/router.go:305-311`). Public
  paths are an explicit small allowlist (`router.go:264-277`).
- **The API is host-networked and reached only via `host.docker.internal`.** Traefik proxies
  to `http://host.docker.internal:${API_PORT}` (`traefik/dynamic.yml.template:108`,
  emitted by `traefik/traefik.go:1320`; compose adds the `host-gateway` mapping,
  `docker-compose.yml:85`). Do not reintroduce an `api` service hostname on the Docker
  network — the api binds the host, not the bridge.
- **Two layers of CSP.** The API sends `default-src 'none'; frame-ancestors 'none'`
  (`router/router.go:392`) plus nosniff/DENY/referrer/permissions headers
  (`router.go:395-408`). The UI is served under a strict `script-src 'self'` CSP from Traefik
  (`traefik/dynamic.yml.template:135-147`). **The page carries no inline scripts** — the SW
  registration was moved out of `index.html` into `main.js` precisely to keep `script-src`
  strict (`ui/src/main.js:44-49`). Never add an inline `<script>` or inline event handler;
  load QR/images as `data:` URLs so they pass `img-src` (see commit `fd1a847`).

### 3.6 Least-privilege Docker access

The api never mounts the raw Docker socket; it goes through `tecnativa/docker-socket-proxy`
with only the capabilities it needs enabled (`docker-compose.yml:21-44`): `CONTAINERS`,
`INFO`, `POST` + `ALLOW_START/STOP/RESTARTS`, `IMAGES`; **`NETWORKS=0`, `VOLUMES=0`**. The one
remaining broad grant, `EXEC=1` (needed for the headscale CLI), is documented as a tracked
follow-up to remove by moving to headscale's REST API (`docker-compose.yml:55-58`). Any new
Docker capability need must be justified the same way.

### 3.7 SSRF guard on outbound fetches

Covered in [§1.6](#16-helper-patterns-context--timeouts): use `SafeExternalHTTPClient` for
any URL an operator can influence. It blocks private, loopback, link-local, multicast,
unspecified, **plus CGNAT `100.64.0.0/10` and `0.0.0.0/8`** at dial time
(`safehttp.go:13-53`) so an SSRF can't reach the VPN overlay plane.

---

## 4. DRY & no dead code

**Extract a shared helper the moment logic would be copied.** Concrete precedents:

- `trustedPanelSources()` is defined once (`panel_access.go:120`) and reused by both the
  panel-access and cloudflare-only tables (`cf_only.go:55`) plus its test.
- `DockerLogConfig()` (`docker_client.go:119`) centralizes bounded json-file logging so every
  panel-created container (turbotunnels `turbotunnels.go:213`, vpn-router `vpn/router.go:256`)
  gets the same log bounds from the same env vars — added specifically because ad-hoc
  containers were defaulting to unbounded logs.
- The rekey `columns` inventory (`rekey.go:34-42`) is the single source of truth for "what is
  encrypted," deliberately noting where it differs from the backup package's list.
- **Periodic background work registers with the routines supervisor**
  (`routines.Register`, `routines.go`), never a bare `go func(){ for range ticker.C { … } }`.
  One supervisor owns the timer loop, panic-recovery, and last/next-run tracking for every job,
  and each becomes visible/controllable on the Routines page for free. `Run` returns an `error`
  (recorded + shown) rather than only logging. When migrating, delete the old ticker goroutine
  — no dead code. See [backend.md](backend.md) §7b for the recipe.
- `allowAndSaddrDropRules()` ([§2](#2-nftables--firewall-code-its-own-sub-discipline)) keeps
  the input/forward chains identical.
- `ParseKey` ([§3.3](#33-secrets-encrypted-at-rest-one-derivation-atomic-rotation)) — one key
  derivation for process + rotation.

**No dead code.** The tree has no `_old`, no commented-out blocks left "just in case," no
unreferenced exports. Non-critical branches are explicitly labeled (e.g.
`vpn_router_config.authkey_enc` is marked `critical=false` / "ephemeral, write-only" rather
than deleted — `rekey.go:41`). If a thing is truly unused, delete it; if it's kept for a
reason, comment the reason.

---

## 5. Frontend — Svelte 5 runes conventions

The UI is Svelte 5 with **runes mode** (`ui/`). See [frontend](./frontend.md) for structure.

- **Props via `$props()` with destructuring + defaults**, and rename reserved names inline:
  `let { variant = 'primary', class: className = '', children, ...restProps } = $props()`
  (`components/Button.svelte:6-21`). Simpler components do it in one line
  (`components/Table.svelte:2`).
- **Local reactive state is `$state(...)`**, derived values are `$derived([...])`
  (`Button.svelte:45-55`). Don't reach for a `writable` store for component-local state.
- **Events are callback props** (`onclick`, `onRowClick`), called optionally with `?.()`:
  `onclick?.(e)` (`Button.svelte:65`). Children render via snippets: `{@render children?.()}`
  (`Button.svelte:88`).
- **Cross-component / app-wide state uses `svelte/store` `writable`** in `ui/src/stores/`
  (theme, current view — `stores/app.js:5,42`), with `localStorage` persistence guarded by
  `typeof localStorage !== 'undefined'` / `typeof window !== 'undefined'`
  (`stores/app.js:4,38-40`). Guard every browser-global access this way.
- **All API traffic goes through the `api()` helper in `stores/app.js`** (`app.js:221`) and
  its `apiGet/apiPost/apiPut/apiDelete` wrappers (`app.js:255-258`). It injects the bearer
  token from `localStorage` via one `getAuthHeaders()` (`app.js:201-206`) and centrally
  handles 401 → global logout (`app.js:238-248`). Never `fetch` an API endpoint directly from
  a component. *(Note: session token currently lives in `localStorage`; moving it to an
  HttpOnly cookie is a known follow-up — don't add new `localStorage.getItem('session_token')`
  call sites.)*
- **KTUI components are imported by exact path**, not the barrel, to avoid pulling the whole
  library (`ui/src/main.js:5-7` and its comment).

---

## 6. Shell / `manage.sh` conventions

`manage.sh` (~120KB) is the operator CLI. It is `set -e` from line 2 and follows tight
conventions:

- **Colored, prefixed output.** Palette defined once at the top (`RED/GREEN/YELLOW/BLUE/CYAN`,
  `NC` reset — `manage.sh:13-18`); status lines use `echo -e "${GREEN}✓${NC} ..."`,
  `${YELLOW}` for progress/warnings, `${RED}` for failures. Diagnostics go to `>&2`
  (`manage.sh:195,199`).
- **Every `.env` mutation goes through `update_env_value KEY VALUE`** (`manage.sh:511-524`),
  which escapes sed metacharacters and either rewrites the existing line or appends. Never
  `sed -i` the `.env` inline in a new code path.
- **Privileged paths re-exec under sudo via `reexec_as_root <subcommand>`**
  (`manage.sh:530-538`) so `/opt`, `/etc/systemd`, `/usr/local/bin` writes "can't
  half-apply." Call it at the top of any command that needs root and pass the subcommand to
  resume.
- **Destructive/lifecycle operations are guarded and reversible.** `rotate_key`
  (`manage.sh:725-800`) is the model: confirm prompt, full DB backup kept until verified,
  stop api for exclusive access, atomic re-encrypt (`api --rekey`), swap key only on success,
  verify under new key (`--rekey-check`), automatic rollback (restore backup + revert key) on
  failure — with a numbered `[n/7]` progress trail. Match this rigor for anything that
  touches the DB or keys.
- **First-install vs. reconfigure guards:** setup paths check for existing `.env` / existing
  state before overwriting (e.g. `[ -f .env ] || { ... exit 1; }` at `manage.sh:733`), so
  re-running is safe.
- **Syntax-check before shipping shell changes:** run `bash -n manage.sh` and, ideally,
  `shellcheck`. Keep secrets file perms tight (`chmod 600 .env`, `chmod 700 backups/` —
  `manage.sh:780,750`).

---

## 7. Testing patterns

Tests are **table-driven, behavior-pinning, and dependency-light** — they lock the *security
invariants*, not implementation detail. Run with `go test ./...` in `api/` and `agent/`.

- **Pin the safety-critical behavior explicitly.** `panel_access_test.go:10-24` asserts the
  fail-OPEN shape ("empty table must contain no drop rule") and that loopback is always
  trusted (`:38-53`). `TestValidCIDROr` (`:26-37`) is a classic table of
  input→expected-fallback cases.
- **Firewall ordering/lint tests:** `firewall_asn_test.go` checks that ASN sets are emitted
  and that rules appear in the correct order within each chain
  (`firewall_asn_test.go:12,190`). `dump_for_lint_test.go` gates real `nft -c` linting behind
  `DUMP_NFT_DIR`.
- **Round-trip / transaction tests with an in-memory-ish SQLite temp DB:** `rekey_test.go`
  spins up a `t.TempDir()` SQLite DB with the real encrypted-column schema
  (`rekey_test.go:17-36`), encrypts with key A, rekeys to key B, and verifies decrypt — using
  fixed hex test keys (`keyA/keyB`, `:12-15`) and `t.Helper()` fixtures.
- The `agent/` package is heavily unit-tested (`enforce_test.go`, `register_test.go`,
  `secrets_test.go`, `selfupdate_test.go`, `manifest_test.go`, …) — new agent logic ships with
  a test.
- **When you change a security invariant, update or add the test that pins it in the same
  change.** A green suite is part of the definition of done.

---

## 8. Commit style

Public repo, **concise Conventional Commits**, no chatter, no emojis (per repo memory
`commit-message-style`). Inspect `git log --oneline`:

```
feat(security): Cloudflare-only web access toggle (L3 firewall)
fix(manage): drop positional args in rebuild so compose up gets no stray service
fix(deps): bump golang-jwt/jwt/v5 5.2.1->5.2.2 (GHSA-mh63-6h87-95cp)
refactor(about): merge source/docs links into Key Feature cards
```

- Format: `type(scope): imperative summary`. Types in use: `feat`, `fix`, `refactor`,
  `chore`, `docs`, `revert`, `harden`. Scopes are the touched area: `security`, `manage`,
  `deploy`, `firewall`/`nftables`, `analytics`, `charts`, `ui`, `settings`, `fleet`,
  `traefik`, `deps`, `migrate`, `qr`, `build`.
- Keep the subject one line and specific ("drop positional args in rebuild so compose up gets
  no stray service" > "fix bug"). Dependency bumps name the CVE/GHSA. Body only when the WHY
  needs more than a line.
- Agent-authored commits also carry the `Co-Authored-By:` / `Claude-Session:` trailers
  configured for the session.

---

## Quick checklist before you commit

- [ ] Handler stays thin; logic in store/service; SQL parameterized.
- [ ] Errors wrapped with `%w` + context; no `log.Fatal` outside boot; no naked 500s.
- [ ] Every value entering an nft rule passed a boundary validator; new rule shapes are
      `nft -c`-lintable.
- [ ] Any restricting firewall behavior **fails open** for the admin path.
- [ ] New encrypted column added to the rekey `columns` inventory.
- [ ] Secrets never logged; outbound operator URLs use `SafeExternalHTTPClient`.
- [ ] No inline `<script>`/handlers; API calls via `stores/app.js` helpers.
- [ ] `.env` edited only via `update_env_value`; `bash -n manage.sh` clean.
- [ ] Non-obvious decision carries a WHY comment naming the failure mode.
- [ ] Behavior-pinning test added/updated; `go test ./...` green.
- [ ] Conventional-commit subject, no emoji.
</content>
</invoke>
