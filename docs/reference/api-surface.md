# API surface

How HTTP endpoints are defined, registered, and protected — plus the main route
groups and the important endpoints per subsystem. This is a map, not an
exhaustive reference; the authoritative list is `api/configs/endpoints.json`
(also served live at `GET /api/schema`).

Related: [backend.md](backend.md) (router mechanism in depth) ·
[security.md](security.md) · [networking-firewall.md](networking-firewall.md) ·
[fleet-agent.md](fleet-agent.md) · [frontend.md](frontend.md).

---

## How endpoints are defined & registered

Routes are **declared as data, bound to code by name** (see
[backend.md §3](backend.md)). In short:

1. `api/configs/endpoints.json` lists each `service` with a `prefix`, an
   `enabled` flag, and `endpoints[]` of `{path, methods, handler, description}`.
2. Each feature package returns a `router.ServiceHandlers`
   (`map[handlerName]func(w,r)`) from `Handlers()`; `main` calls
   `r.RegisterService("<service>", svc.Handlers())`.
3. `router.Build()` binds `prefix+path` → the named handler, grouping by mux
   pattern and dispatching by path + method. `{id}` path params and a trailing
   `{keys...}` catch-all are supported. Wrong method on a known path → **405**,
   unknown path → **404**, both as JSON `{"error": "..."}`.

To add an endpoint you add a JSON entry **and** a handler in the map — no route
code. A disabled service (or missing handler) is skipped with a boot warning.

**Prefix convention:** everything is under **`/api`**. Each subsystem gets a
short prefix (`/api/wg`, `/api/fw`, `/api/hs`, …). Three non-`/api`-schema paths
are registered directly by the router (`/api/schema`, `/api/manifest.json`,
`/health`), and a few routes are mounted directly on the outer mux, outside the
config system (`/api/ws`, `/internal/*`, `/agent/{token}` — see below).

---

## Auth & middleware

Middleware wraps every request (order as applied, outer→inner): **CORS →
security headers → request logging → 10 MB body-size limit → rate limit
(token-bucket per client IP) → auth**. Auth is innermost so it rejects before
work happens. (`api/internal/router/router.go`.)

**Auth model** (`authMiddleware`, `router.go:262`):
- Bearer token from the `Authorization` header or cookie
  (`helper.ExtractBearerToken`), validated by the auth service's
  `ValidateSession` (registered via `router.SetAuthValidator`).
- **Public paths** (no token required):
  - prefixes: `/api/setup/`, `/api/auth/login`, `/api/restart/`, `/api/hook/`
  - exact: `/health`, `/api`, `/api/`, `/api/manifest.json`
  - all `OPTIONS` (CORS preflight)
- **Fail closed**: if no auth validator is registered (auth disabled or failed
  to init), protected paths return `503` rather than serving unauthenticated.
- Rate limiting is per client IP (`helper.GetClientIP`, which honors
  `CF-Connecting-IP` only for verified Cloudflare ranges); `/health` is exempt.
- WebSocket (`/api/ws`) is **not** protected by this middleware — it upgrades
  then authenticates on the first message (see [backend.md §6](backend.md)).

The public `/api/restart/` and `/api/hook/` endpoints carry their **own**
per-key secrets in the path instead of a session (see turbotunnels below).

---

## Route groups (per subsystem)

Prefixes and the notable endpoints. All are session-authed unless marked
**public**. Methods shown where they matter.

### auth — `/api/auth`
Login/session/2FA. `POST /login` (**public**), `POST /logout`, `GET /me`,
`POST /users` (create admin), `GET /sessions`,
`POST /sessions/{id}/revoke`, `POST /sessions/revoke-others`,
`POST /change-password`, and TOTP 2FA: `GET /2fa/status`, `POST /2fa/setup`,
`POST /2fa/enable`, `POST /2fa/disable`. Web-push/PWA lives under `/api/pwa`
(vapid key, subscribe/unsubscribe, preferences, device locations, test).

### setup — `/api/setup` (**public** prefix)
First-run wizard, usable before a session exists: `GET /status`,
`GET /detect-headscale`, `POST /generate-apikey`, `POST /test-headscale`,
`POST /complete`.

### wireguard (peers) — `/api/wg`
Peer CRUD: `GET /peers`, `POST /peers`, `GET|PUT|DELETE /peers/{id}`,
`POST /peers/{id}/enable|disable`, `POST /peers/{id}/block-internet|unblock-internet`.
Client provisioning: `GET /peers/{id}/config`, `GET /peers/{id}/qr`.
Live: `GET /sessions`, `GET /server`. Per-peer virtual IPs:
`GET|POST /peers/{id}/vips`, `DELETE /vips/{vipId}`, `PUT /vips/{vipId}/acl`,
`GET /vips/{vipId}/commands`.

### headscale — `/api/hs`
Admin wrapper over the Headscale REST API. Users: `GET|POST /users`,
`DELETE /users/{name}`, `PUT /users/{name}/rename/{newName}`. Nodes:
`GET /nodes`, `DELETE /nodes/{id}`, `POST /nodes/{id}/rename/{name}`,
`POST /nodes/{id}/expire`, `GET /nodes/{id}/routes`, `PUT /nodes/{id}/tags`.
Routes: `GET /routes`, `POST /routes/{id}/enable|disable`, `DELETE /routes/{id}`.
Keys: `GET|POST /preauthkeys`, `POST /preauthkeys/expire`,
`GET|POST /apikeys`, `DELETE /apikeys/{id}`.

### vpn (unified clients + ACL) — `/api/vpn`
Combined WireGuard+Headscale client view and ACL engine: `GET /clients`,
`GET /clients/{id}`, `PUT /clients/{id}/acl`, `PUT /clients/{id}/dns`,
`POST|DELETE /clients/{id}/scan` (port scan), `POST /apply` (regenerate + apply
ACL), `POST /traffic/reset`. Subnet router (Headscale): `GET /router/status`,
`POST /router/setup`, `POST /router/restart`, `DELETE /router`.

### firewall — `/api/fw`
The gate. Status/overview: `GET /status`, `GET /overview`, `GET /layers`,
`GET /sync-status`, `POST /stats/clear`. Entries (unified IP/range/country/ASN):
`GET|POST /entries`, `DELETE /entries/{id}`, `POST /entries/{id}/toggle`,
`POST /entries/bulk`, `POST /entries/import`, `DELETE /entries/source/{source}`,
`DELETE /entries/all`. Ports: `GET|POST /ports`, `DELETE /ports/{port}`.
Jails (fail2ban-style): `GET|POST /jails`, `GET|PUT|DELETE /jails/{name}`.
Config/apply: `GET|PUT /config`, `POST /apply`, `POST /ssh` (change SSH port),
`GET /blocklists`.

### domains / traefik — `/api/domains`, `/api/traefik`
Reverse-proxy routes: `GET|POST /domains`, `GET|PUT|DELETE /domains/{id}`,
`POST /domains/{id}/toggle`, `GET /domains/certificates`,
`GET /domains/system-domain(s)`. Traefik control: `GET /traefik/overview`,
`GET|PUT /traefik/config`, `GET|POST /traefik/vpn-only`,
`GET|POST /traefik/fw-block` (L7 firewall-block toggle), `GET /traefik/resolvers`.
AdGuard sits alongside at `/api/adguard` (`GET /overview`, `PUT /config`,
`GET|PUT /filtering`, `GET|PUT /rewrites`).

### logs / analytics — `/api/logs`
`GET /logs` (query with pagination/filters), `DELETE /logs`, `GET /logs/stats`,
`GET /logs/status`, `GET /logs/top-talkers`, `GET|DELETE /logs/peer-usage`,
`POST /logs/watcher` (enable/disable a source watcher). Live host resource
stats and container stats are pushed over WebSocket, not REST.

### geolocation — `/api/geo`
`GET|PUT /settings`, `GET|POST /lookup` (single/bulk IP → country/ASN),
`GET /asn/search`, `GET /status`, `POST /update` (refresh DBs),
`GET /countries`, `POST /zones/refresh`, and enrichment-DB management
`GET /enrichment`, `POST /enrichment/download`, `DELETE /enrichment`.

### fleet — `/api/fleet` (admin side)
Panel-side management of the agent fleet: tokens `POST /token`, `GET /tokens`,
`DELETE /tokens`; machines `GET /machines`, `POST /machine/delete`,
`GET /machine/commands`; CA `GET /ca`; commands `POST /command`; telemetry
`GET /report`, `GET /metrics`, `GET /endpoints`; config `POST /config`,
`POST /push-blocks`; CVEs `GET /cves`, `GET /cves/groups`, `GET /cves/by-cve`,
`GET /cves/export`, `POST /fix`. The **agent-facing** endpoints are on a
separate mTLS listener, not `/api` (see below and [fleet-agent.md](fleet-agent.md)).

### turbotunnels — `/api/turbotunnels` (+ public triggers)
Optional forward-proxy container control: `GET /status|stats|overview|config`,
`PUT /config`, `POST /test`, `POST /credentials`, `POST /quick-deploy`,
`POST /start|stop|restart`. Two **public** trigger groups authenticated by
per-key secrets in the path (registered as separate services `rotate` +
`webhook`): `GET|POST /api/restart/{key}` (tunnel rotation) and
`GET|POST /api/hook/{keys...}` (webhook pass-through, catch-all path). Both
bypass session auth by design.

### settings — `/api/settings`
Key-value settings store: `GET /settings` (read), `POST /settings`
(select a subset), `PUT /settings` (update). Encrypted values are stored via the
`settings` package's encrypted variants.

### backup — `/api/backup`
Passphrase-encrypted config export/import: `POST /export`, `POST /preview`,
`POST /import`. Import is a faithful REPLACE that then reconciles live state
(firewall, VPN, fleet) via callbacks injected in `main`.

### server (host security) — `/api/server`
Read-only host telemetry for the "Server" page: `GET /security`,
`DELETE /sudo-failure/{id}`.

### events — `/api/events`
`GET /events?limit=&type=&subsystem=` — the cross-subsystem activity feed.

### docker — `/api/docker`
`GET /containers`, `GET /containers/{name}`,
`POST /containers/{name}/restart|stop|start`, `GET /images/{name}/analyze`.

---

## Non-`/api` routes (mounted on the outer mux)

These are registered directly in `main` on the outer `http.ServeMux`, **outside**
the config-driven router, so they bypass the session-auth middleware:

- **`GET /api/ws`** — WebSocket upgrade (`wsSvc.HandleWebSocket`). Authenticates
  via the first message, not the middleware.
- **`/internal/blocklist`** and **`/internal/l7block`** — the Traefik **sentinel
  plugin** feed. `/internal/blocklist` serves the firewall's current
  block-list; `/internal/l7block` ingests the sentinel's periodic L7 block
  count. Both are fetched container-to-container over the Docker network, never
  routed by Traefik, and the handlers **refuse proxied requests** — they are not
  reachable from outside. Registered only when the firewall service is up.
- **`GET /agent/{token}`** — fleet self-extracting agent installer
  (`flSvc.HandleInstallScript`). Bypasses auth because a new machine has no
  session; the one-time token in the path is the credential. Reached via
  Traefik/443 on the panel domain, with rate-limit + blocklist middleware in
  front (fleet route).

## Fleet agent mTLS listener (separate port)

The fleet agents do **not** talk to `/api`. When fleet is enabled it opens its
own TLS listener (port from the `fleet_port` setting) with these routes
(`api/internal/fleet/listener.go`):

- `POST /enroll` — the join door, gated by an enrollment token (not mTLS yet).
- `GET /healthz` — liveness.
- mTLS-gated (client cert required, `requireClientCert`): `POST /report`,
  `POST /cve-report`, `GET /commands`, `POST /commands/ack`,
  `POST /deregister`.

See [fleet-agent.md](fleet-agent.md) for the enrollment/CA/mTLS flow.

## Built-in router endpoints

Registered by `router.Build()` itself (not via a feature package):
`GET /api/schema` (**public** — enabled services + endpoints + `version` +
`panel_version`), `GET /api/manifest.json` (**public** — dynamic PWA manifest,
needs `SSL_DOMAIN`), `GET /health` (**public** — DB + Headscale health, returns
`503` when degraded).

---

## Unverified / notes

- Method lists and handler names above are transcribed from
  `api/configs/endpoints.json`; the per-endpoint request/response bodies live in
  each package's handler and are not reproduced here.
- Whether an individual handler enforces extra authorization beyond the session
  (e.g. admin-only) is per-handler and not audited in this doc — see
  [security.md](security.md).
