# Backend (Go API)

How the Go backend is organized, so the structure can be reproduced in any
language. The backend is a single statically-linked binary (`api`) that runs as
one process, host-networked, and serves the whole panel's REST + WebSocket API.

Related: [architecture.md](architecture.md) · [api-surface.md](api-surface.md) ·
[data-model.md](data-model.md) · [networking-firewall.md](networking-firewall.md) ·
[security.md](security.md) · [fleet-agent.md](fleet-agent.md).

- Entry point: `api/cmd/main.go` (+ `bootstrap.go`, `rekey_cmd.go`)
- Feature code: `api/internal/**`
- Static config: `api/configs/*.json`
- Module path is `api` (imports look like `api/internal/router`).

---

## 1. Package layout (`api/internal`)

Each feature lives in its own package. Most expose a `Service` type with a
`Handlers() router.ServiceHandlers` method; a few are pure libraries or
one-shots. Enumerated:

| Package | Role (one line) |
|---|---|
| `router` | HTTP router + all middleware (auth, CORS, rate-limit, logging, security headers), plus shared JSON/response/pagination helpers. Everything routes through here. |
| `config` | Loads `configs/endpoints.json` into typed structs; exposes `IsServiceEnabled`, per-subsystem app config (firewall/session/websocket). |
| `database` | Shared SQLite handle + `*DB` wrapper, schema creation, and in-code migrations. `Init`, `Get`, `GetDB`. |
| `helper` | Cross-cutting utilities: encryption (`Encrypt`/`Decrypt`, `InitEncryption`), env access (`GetEnv`), Docker client, Headscale HTTP client, IP/CIDR + client-IP extraction, safe HTTP, port scanner, validation, YAML. |
| `auth` | Login, sessions, bcrypt password auth, TOTP 2FA, session cleanup, rate limiting. `auth/pwa` sub-package = web-push notifications, prefs, device locations. Registered first; others depend on it for encryption/session. |
| `settings` | Key-value settings store (`settings` table), plaintext + encrypted variants. Holds many cross-subsystem toggles; uses function-pointer callbacks set by `main` to avoid import cycles. |
| `setup` | First-run setup wizard: status, Headscale detection/test, API-key generation, completion. |
| `events` | Cross-subsystem activity feed (`events` table). Package-level best-effort `Log(subsystem, type, severity, message)`; self-trimming. |
| `routines` | Supervisor for periodic background jobs — a **leaf package** (stdlib only) so any package can `Register` a `Spec` without an import cycle. Owns the timer loop, records last/next-run + result, and exposes `RunNow`/`Pause`/`Resume`. |
| `routinesapi` | Thin HTTP layer over `routines` (`/api/routines` list + run/pause/resume). Separate from the core so the core stays router-free. |
| `wireguard` | WireGuard peer CRUD, client config + QR generation, live sessions, per-peer virtual IPs. Uses a `PeerStore` (DB-backed cache). |
| `headscale` | Thin admin wrapper over the Headscale REST API (users, nodes, routes, pre-auth keys, API keys) via `helper.HeadscaleGet/...`. |
| `vpn` | Unified VPN-client view (WireGuard + Headscale) + ACL engine, DNS toggles, port scanning, traffic sync, subnet-router (Headscale) management. Generates the Headscale ACL and the nftables VPN-ACL table. |
| `firewall` | The gate: unified `firewall_entries` (IP/range/country/ASN/port), fail2ban-style jails, blocklists, L3/L7 stats, dashboard security summary, internal blocklist feed for the Traefik sentinel. Drives `nftables`. |
| `nftables` | Low-level nftables ruleset builder + applier. Owns registered "tables" (VPN-ACL, panel-access, Cloudflare-only). Safety is per-boundary input validation + an atomic single-transaction `nft -f` apply (not a separate `nft -c` pass); see [networking-firewall.md](networking-firewall.md). |
| `geolocation` | IP → country/ASN lookup (MaxMind / IP2Location / ipdeny), ASN range expansion, reputation, enrichment DB downloads. Firewall depends on it for country/ASN blocking. |
| `domains` | Domain routes for Traefik reverse proxy (`domain_routes` table); regenerates dynamic Traefik config. |
| `traefik` | Reads/writes Traefik config (core + dynamic), VPN-only mode, L7 firewall-block toggle, cert/resolver info. |
| `adguard` | Wrapper over AdGuard Home's API (overview, filtering, rewrites); credentials come from settings. |
| `docker` | Container ops (list/start/stop/restart, stats, log streaming, image analysis) via a docker-socket-proxy. Feeds dashboard health + WS. |
| `logs` | Log ingestion + query. `Service` manages watchers (`logs/sources`: traefik, adguard, outbound, conntrack), hourly rollups, retention, top-talkers, per-peer usage. |
| `turbotunnels` | Optional forward-proxy container lifecycle; public rotation + webhook triggers; auth-log streaming into firewall jail + logs. |
| `fleet` | Per-machine fleet agent backend (Phase 2): panel CA, agent enrollment, machine registry, mTLS listener, command queue, metrics, CVE tracking, self-extracting installer. See [fleet-agent.md](fleet-agent.md). |
| `backup` | Passphrase-encrypted export / faithful-replace import of the whole panel config; reconciles live state after import via injected callbacks. |
| `server` | Read-only host-security telemetry for the "Server" page (logins, sudo, new accounts, package installs, listening ports, uptime, TLS certs). |
| `serverstats` | Single `/proc` collector broadcasting host CPU/mem to the `server_stats` WS channel; subscriber-gated. |
| `stats` | Process-level stats (uptime, mem, goroutines, GC, WS client count) for the dashboard. |
| `retention` | Central pruning of aggregate rollup tables to one settings-driven window; constant table names only. |
| `rekey` | One-shot re-encryption of every at-rest secret under a new `ENCRYPTION_SECRET` (`api --rekey`). Pre-flight decrypt-all before committing. |

Sub-packages: `auth/pwa`, `logs/sources`.

The typical **naming convention** inside a package:
- `service.go` or `<pkg>.go` — `Service` struct, `New`, `Handlers()`.
- `handlers.go` / `*_handlers.go` — HTTP handler methods (`handleXxx`).
- `store.go` / `<thing>store.go` / `types.go` — persistence + domain types.

---

## 2. Entry point — boot sequence (`api/cmd/main.go`)

`main()` runs a fixed sequence (`api/cmd/main.go:49`):

1. **Re-key one-shot branch** (`main.go:52`, `rekey_cmd.go`). If `os.Args[1]` is
   `--rekey` or `--rekey-check`, `maybeRunRekey()` handles it and returns `true`
   so `main` exits **without** starting servers. These run with the main api
   stopped (exclusive DB access). `--rekey` reads `ENCRYPTION_SECRET` (old) +
   `ENCRYPTION_SECRET_NEW`, refuses rotating *to* a weak key, and re-encrypts
   every secret in one transaction; `--rekey-check` verifies all secrets
   decrypt under the current key. See `rekey_cmd.go` + package `rekey`.
2. **`stats.Init()`** — record start time for uptime.
3. **Load config** (`config.Load`) from `CONFIG_PATH`
   (`/app/configs/endpoints.json`). Fatal on failure.
4. **`router.New(cfg)`** — create the router; stamp `router.PanelVersion` from
   the link-time `version` var (surfaced at `/api/schema`).
5. **`database.Init(DATA_DIR)`** — open `app.db` (SQLite, WAL, foreign keys on),
   create schema, run migrations. Fatal on failure.
6. **`helper.InitEncryption()`** — derive the at-rest key from
   `ENCRYPTION_SECRET`. If the secret isn't 32-byte hex, `WeakEncryptionKey` is
   set and a warning is written to the Activity feed (the DB is already up).
7. **`routines.Init(ctx)`** then **`helper.StartCloudflareIPUpdater()`** — start
   the background-routine supervisor, then register the Cloudflare edge-range
   refresh (runs on start + every 24h) as a supervised, page-controllable job.
8. **Service registration** (see §3). Order matters and is intentional:
   - `auth` **first** (others depend on it). On success it registers the
     `router.SetAuthValidator` used by the auth middleware.
   - then `pwa`, `setup`, `events` (always on), `settings`, `geolocation`
     (before firewall), `nftables` (before firewall + vpn), `firewall`,
     `wireguard`, `traefik`, `headscale`, `adguard`, `docker`, `vpn`,
     `domains`, `turbotunnels`, `logs`, `retention` (background), `server`,
     `fleet`, `backup`.
   - Most services are gated by `config.IsServiceEnabled("<name>")`. `nftables`
     and `backup` are always constructed.
9. **Background tasks** started during registration: auth cleanup
   (`authSvc.Start()`), Cloudflare updater, VPN traffic sync
   (`vpn.StartTrafficSync`), turbotunnels log streamer + rotate-guard cleanup,
   log watchers (`logsSvc.Start()`), `retention.Start`, serverstats collector
   (`serverstats.New(...).Run()`), WS status checker (`ws.StartStatusChecker`).
10. **WebSocket + providers**: `ws.New()` starts the hub; `main` wires provider
    callbacks into `ws` (overview stats, docker containers/stats/logs, node
    stats) — see §5.
11. **Build the HTTP handler**: `r.Build()` produces the middleware-wrapped mux,
    then `main` creates a second `http.ServeMux` that mounts:
    - `/api/ws` → `wsSvc.HandleWebSocket`
    - `/internal/blocklist`, `/internal/l7block` → firewall (bypass auth; refuse
      proxied requests) — for the Traefik sentinel plugin
    - `GET /agent/{token}` → fleet self-extracting installer (bypass auth)
    - `/` → the main router handler
12. **`http.Server`** with 30s read/write + 60s idle timeouts, listening on
    `API_PORT`. A goroutine handles `SIGINT`/`SIGTERM` for graceful shutdown
    (server shutdown, stop WS checker, stop traffic sync, close DB).

`bootstrap.go` holds `bootstrapAdGuardPasswordFromFile` — a one-shot first-boot
migration that encrypts a plaintext AdGuard password written by `manage.sh` into
the settings DB, then deletes the plaintext file. Called during AdGuard
registration.

**Dependency inversion via function pointers.** To avoid import cycles, `main`
injects callbacks between packages instead of letting them import each other —
e.g. `settings.RequestFirewallApply = nftSvc.RequestApply`,
`traefik.RegenerateDomains = domains.ApplyRoutes`,
`helper.SetHeadscaleConfigProvider(...)`, `ws.SetOverviewStatsProvider(...)`.
This is the dominant cross-package wiring pattern; grep `main.go` for `= func`
and `Set...` to see the full set.

---

## 3. Router / service-registration pattern

The router is **config-driven**. Routes are *not* declared in Go; they're
declared as data in `configs/endpoints.json` and bound to handler functions by
name.

- `api/internal/config/config.go` defines the schema: a `Config` has
  `Services map[string]ServiceConfig`; each service has a `Prefix`, `Enabled`
  flag, and a list of `EndpointConfig{Path, Methods, Handler, Description}`.
- A feature package's `Handlers()` returns a `router.ServiceHandlers`
  (`map[string]HandlerFunc`) — keyed by the **handler name** used in the JSON.
- `main` calls `r.RegisterService("<name>", svc.Handlers())`
  (`router.go:52`). The service name must match the key in `endpoints.json`.
- `r.Build()` (`router.go:57`) walks the config: for each enabled service and
  each endpoint, it looks up the handler by name, computes the full pattern
  (`prefix + path`), and groups handlers by their **actual mux pattern**
  (the pattern truncated at the first `{`). One combined `HandleFunc` per actual
  pattern then dispatches by matching the full pattern (`pathMatches`, with
  `{param}` and trailing `{name...}` catch-all support) and method
  (`methodAllowed`). Non-matching path → 404; matching path, wrong method → 405.

So adding an endpoint = add a JSON entry + a handler in the `Handlers()` map.
Missing handler or missing service logs a warning at boot and is skipped.

`r.Build()` also registers three built-in routes directly on the mux:
`/api/schema` (lists enabled services + endpoints + versions), `/api/manifest.json`
(dynamic PWA manifest), `/health` (DB + Headscale health checks).

**Middleware** is applied in `applyMiddleware` (`router.go:219`), outermost to
innermost as wrapped: CORS → security headers → logging → body-size limit
(10 MB) → rate limit (token bucket per client IP) → **auth** (innermost, so it
rejects early). Auth is described in [api-surface.md](api-surface.md) and
[security.md](security.md).

The `router` package also provides the shared response/request helpers every
handler uses: `JSON`, `JSONWithStatus`, `JSONError`, `DecodeJSON(OrError)`,
`ParsePagination`, `ExtractPathParam(Int/Full/Segment)`, `QueryParam(Int)`,
`ParseIDOrError`.

---

## 4. Shape of a feature package

The common split is **handlers + service/store**. Three concrete examples:

### `events` (minimal, stateless)
- `events.go` — the store logic: package-level `Log(...)` inserts into the
  `events` table (best-effort; errors swallowed), self-trims to `maxRows`, and
  `List(limit, type, subsystem)` reads back.
- `handlers.go` — `Service` (empty struct), `New()`, `Handlers()` returning one
  handler `"ListEvents"` → `handleList`, which parses query params and calls
  `List`. Illustrates the smallest possible service.

### `wireguard` (service + store split)
- `wireguard.go` — `Service{config, peerStore}`, `New`, `Handlers()` (18 handler
  names: peer CRUD, config/QR, sessions, virtual IPs), and pure helpers like
  `generateClientConfig`. A package-level `serviceInstance` + `SetService`/
  `GetService` lets other packages reach it (a recurring pattern:
  `wireguard`, `geolocation`, `firewall`, `vpn`, `ws` all do this).
- `peerstore.go` — `PeerStore` (a `sync.RWMutex`-guarded in-memory cache backed
  by the DB, with legacy `peers.json` migration). This is the "store".
- `handlers.go`, `sessions.go`, `virtualips.go`, `interface.go` — HTTP handlers
  and subsystem logic split by concern.

### `firewall` (larger, many files, one service)
- `service.go` — `Service`, `New(dataDir, nftSvc)`, `Handlers()` (26 handlers),
  `SyncAndReapply`, `RequestApply`. Depends on `geolocation`, `nftables`,
  `database`, `ws`.
- Concern-split files: `entries_handlers.go`, `ports_handlers.go`,
  `jails_handlers.go` (handlers); `blocking.go`, `blocklist.go`, `jail.go`,
  `layers.go`, `traffic.go`, `l3stats.go`, `l7stats.go` (logic);
  `blocklist_internal.go` (the `/internal/*` sentinel feed); `types.go`.

So a package scales from one file (`events`) to ~18 files (`firewall`) but keeps
the same contract: a `Service` with `New` + `Handlers()`, handler methods named
`handleXxx`, and persistence in a store/DB layer.

---

## 5. DB access (`api/internal/database`)

- **Single shared handle.** `Init(dataDir)` (once, via `sync.Once`) opens
  `<dataDir>/app.db` with `sqlite3` and DSN
  `?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=1`. FK enforcement is on
  per-connection so the schema's `ON DELETE CASCADE`/`SET NULL` actually fire.
  Driver: `github.com/mattn/go-sqlite3` (CGo).
- **`*DB` wrapper** (`database.go:22`) embeds `*sql.DB` and adds a default 30s
  timeout: `Exec` uses `ExecContext` with the timeout; `Query`/`QueryRow`/`Begin`
  call the embedded `sql.DB` directly (SQLite compatibility). Accessors:
  `Get()` → raw `*sql.DB` (legacy), `GetDB()` → `*DB` (preferred).
- **Schema** lives in `createSchema` as raw `CREATE TABLE IF NOT EXISTS` blocks
  grouped by domain (firewall, app, vpn, logs, user-PWA). See
  [data-model.md](data-model.md) for the tables.
- **Migrations** are hand-rolled in `runMigrations`: check `pragma_table_info`
  for a missing column then `ALTER TABLE ADD COLUMN`; for CHECK-constraint
  changes (SQLite can't ALTER a CHECK) it rebuilds the table inside a
  transaction, copying columns explicitly. No external migration framework.
- **Helpers** (`helpers.go`): `EscapeLikePattern` and `XxxFromNull` converters
  for `sql.Null*` → concrete types with defaults.
- After schema init, a `PRAGMA foreign_key_check` sweep logs any pre-existing FK
  violations loudly (enabling FK doesn't retroactively validate old rows).

---

## 6. WebSocket hub (`api/internal/ws`)

- `ws.go` — `Service{hub, upgrader}`, `New()` (starts `hub.Run()` in a
  goroutine), and the exported broadcast API used by other packages:
  `Broadcast(channel, payload)`, `BroadcastAll`, `BroadcastToUser`,
  `ClientCount`, `ChannelSubscriberCount`. A package-global `serviceInstance`
  backs the package-level functions.
- **Auth on connect, not on upgrade.** `HandleWebSocket` upgrades first, then
  requires the first message to be `{"action":"auth","token":"..."}` and
  validates it via `auth.GetService().ValidateSession`. The token is never
  accepted in the URL (would leak into logs/history). Origin is checked against
  the CORS allow-list in `checkOrigin`.
- `hub.go` — the `Hub`: maps of `clients`, `subscriptions` (channel → clients),
  and `userClients` (userID → clients), driven by `register`/`unregister`/
  `broadcast` channels in a single `Run()` select loop (so hub state needs no
  lock on the hot path beyond the RWMutex it holds). Clients subscribe to
  named channels; broadcasts fan out only to subscribers, dropping messages
  when a client's send buffer is full (never blocks the hub).
- `client.go` — per-connection `Client` with `ReadPump`/`WritePump`, a buffered
  `send` channel, and a `done` channel; handles `subscribe`/`unsubscribe`/
  docker-log-container messages.
- `broadcaster.go` — the periodic push loop + provider indirection: `main`
  registers providers (`SetOverviewStatsProvider`, `SetDockerProvider`,
  `SetContainerStatsProvider`, `SetDockerLogStreamer`, `SetNodeStatsProvider`)
  and the status checker (`StartStatusChecker`) polls them and broadcasts.
  Expensive collectors are **subscriber-gated** via `ChannelSubscriberCount`,
  so they idle when no page is watching.
- **Channels** (declared in `endpoints.json` → `app.websocket.channels`):
  `general_info`, `nodes_updated`, `docker`, `docker_logs`, `stats`, `fleet`,
  `server_stats`, `container_stats`.

---

## 7. Events / activity feed (`api/internal/events`)

- One chronological, cross-subsystem feed backed by the `events` table
  (`id, created_at, type, severity, subsystem, message`).
- **Producer API**: package-level `events.Log(subsystem, eventType, severity,
  message)`. Best-effort — any DB error is logged and swallowed so recording
  never breaks the caller. Severities: `info`, `warning`, `critical`.
- **Bounded**: self-trims to the newest `maxRows` (2000) every `trimEvery` (100)
  inserts, using an atomic counter to avoid locking the hot path.
- **Consumer API**: `List(limit, typeFilter, subsystemFilter)` (limit clamped
  ≤ 500) emits `created_at` as ISO-8601 UTC. Exposed at `GET /api/events`
  (see [api-surface.md](api-surface.md)).

---

## 7b. Background routines (`api/internal/routines`)

The panel runs many periodic background jobs (Cloudflare-IP refresh, cleanups, samplers…). Historically each was a private `go func(){ for range ticker.C { … } }` — invisible and only changeable by an api restart. The `routines` **supervisor** makes them visible and controllable.

- **Register instead of `go func`:** a job calls `routines.Register(routines.Spec{Name, Description, Interval, RunAtStart, Run})`. The supervisor owns the timer loop, recovers panics, and records `LastRun`/`LastDuration`/`LastError`/`NextRun`/`Runs`/`Status`.
- **Leaf package:** `routines` imports only the standard library, so *any* package (even `helper`) can register without an import cycle. The HTTP layer lives in the separate `routinesapi` package (imports `routines` + `router`).
- **Control:** `RunNow` / `Pause` / `Resume` (run-now overrides pause). Exposed at `/api/routines` (see [api-surface.md](api-surface.md)) and surfaced on the **Routines** page.
- **Lifecycle:** `main` calls `routines.Init(ctx)` early (§2 step 7); `Register` before `Init` queues, after `Init` starts the loop immediately.
- **Migration status:** Phase 1 migrated `cloudflare-ips` (`helper/ip.go`) and `session-cleanup` (`auth/cleanup.go`). Other periodic jobs still run as private goroutines and move over incrementally. Jobs whose schedule is hour-of-day (e.g. the daily geolocation update) await interval-vs-cron support and are not yet migrated.

---

## 8. Config (`api/internal/config`, `api/configs/`)

- `config.Load(path)` reads and unmarshals `endpoints.json` into the `Config`
  struct once; `Get`, `GetService`, `IsServiceEnabled`, and typed getters
  (`GetFirewallConfig`, `GetSessionConfig`, `GetWebSocketConfig`) expose it with
  sane defaults when zero.
- **`endpoints.json`** (the routing manifest, ~1700 lines) drives §3 — it holds
  `version`, `app` (firewall/session/websocket tunables + WS channel list),
  `services` (prefix/enabled/endpoints), and `middleware` (cors/logging/
  ratelimit). Path is set by `CONFIG_PATH` (compose: `/app/configs/endpoints.json`).
- Other static config files in `api/configs/` are **data**, loaded by their own
  packages, not by `config`: `common-ports.json`, `essential-ports.json`,
  `countries.json`, `blocklist-sources.json` (firewall), `geolocation.json`
  (geolocation).
- **Runtime** configuration (as opposed to this static config) lives in the DB
  `settings` table via the `settings` package; env vars provide only
  process-level inputs: `CONFIG_PATH`, `DATA_DIR`, `API_PORT`,
  `ENCRYPTION_SECRET`, `SSL_DOMAIN` (see [deployment.md](deployment.md)).

---

## Unverified / notes

- Package one-liners for packages without a doc-comment (`adguard`, `docker`,
  `domains`, `geolocation`, `headscale`, `nftables`, `settings`, `stats`,
  `traefik`, `vpn`) were inferred from the `Service`-struct comment, filenames,
  and `main.go` registration — accurate at a summary level; consult each
  package's source for exact responsibilities.
- The exact set of `broadcaster.go` providers/intervals was read from `main.go`
  wiring and `ws.go`; the internal loop timing lives in
  `ws/broadcaster.go`/`client.go` (not fully quoted here).
