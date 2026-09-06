# Architecture

High-level map of the WireGuard Admin Panel: what it is, the components it ships, how they are wired into containers and networks, and the design invariants that hold the whole thing together.

> Sibling docs: [README](./README.md) · [backend](./backend.md) · [api-surface](./api-surface.md) · [data-model](./data-model.md) · [security](./security.md) · [networking & firewall](./networking-firewall.md) · [frontend](./frontend.md) · [deployment](./deployment.md) · [fleet agent](./fleet-agent.md) · [coding standards](./coding-standards.md) · [rebuild from scratch](./rebuild-from-scratch.md)

---

## 1. What it is and who it's for

A single self-hosted control panel that unifies a full networking stack behind one authenticated UI and REST API:

- **WireGuard** peer management (manual kernel WireGuard, via `wgctrl`).
- **Headscale** control plane for Tailscale-compatible clients.
- **AdGuard Home** DNS filtering + query logging.
- **Traefik** reverse proxy for admin access and user-defined domain routes.
- An **nftables firewall** managed directly by the Go backend (rules, jails, geo-blocking, blocklists).
- **turbotunnels** — authenticated HTTP/SOCKS5 forward proxies, created on demand.
- A per-machine **fleet agent** (git-ignored `agent/`) that enrolls over mTLS and reports metrics + CVE scans.

Audience: a single operator (or small team) running their own VPN/networking box on a Linux host with root, Docker, and the WireGuard kernel module. It is an *admin plane*, not a multi-tenant SaaS — there is one privileged panel that manages the host it runs on.

The authoritative capability list, the running build version, and a live API reference are all shown on the panel's **About** page (schema served from `/api/schema`, see [`router.go:502`](../../api/internal/router/router.go)).

---

## 2. Component inventory

Source of truth: [`docker-compose.yml`](../../docker-compose.yml). Every container uses bounded json-file logging (`x-logging` anchor).

| Component | Image / build | Network mode | Role |
|-----------|---------------|--------------|------|
| **traefik** | `traefik:v3.6` | `vpn-network` (static IP `TRAEFIK_CONTAINER_IP`) | Edge reverse proxy. Terminates 80/443 (+ 8080 dashboard). Routes admin UI, the unified API, the Headscale control plane, and user domain routes. Hosts the custom **sentinel** local plugin. |
| **api** | built from `./api` (Go) | `network_mode: host`, `pid: host`, `privileged`, `NET_ADMIN` | The brain. One Go binary exposing every `/api/*` service, driving nftables/WireGuard on the host, and orchestrating the other containers via the Docker socket proxy. Host-networked so it can manage the kernel firewall and WireGuard directly. |
| **ui** | built from `./ui` (Svelte 5 → nginx) | `vpn-network` (static `UI_CONTAINER_IP`) | Static SPA served by nginx on port 80; Traefik proxies `/`. Talks only to the API. |
| **headscale** | `headscale/headscale:0.25` | `vpn-network` (static `HEADSCALE_CONTAINER_IP`) | Tailscale-compatible coordination server. Exposes STUN/DERP (`3478/udp`, direct `8443`) and an internal API bound to `127.0.0.1:8085`. |
| **adguard** | `adguard/adguardhome:latest` | `network_mode: host` | DNS server (`:53`) + filtering + query log. Host-networked to serve DNS on the host and to VPN clients. |
| **docker-socket-proxy** | `tecnativa/docker-socket-proxy` | `socket-proxy-net` (isolated) | Filtered Docker API on `127.0.0.1:2375`. The api reaches Docker through this proxy, never the raw socket. Allows containers/logs/start/stop/restart/exec/images; denies build, volumes, networks, secrets, swarm. |
| **vpn-router** | `tailscale/tailscale:latest` | `network_mode: host`, `NET_ADMIN`/`NET_RAW` | Optional (`profiles: [vpn-router]`). Advertises the WireGuard subnet into the Headscale/Tailnet so the two VPNs can route to each other (subnet router). |
| **turbotunnels** | built from `./turbotunnels` | `vpn-network` (static IP), `profiles: [turbotunnels]` | Compose entry only defines how to **build** the image. At runtime the api creates the real container itself via the Docker API, injecting the encrypted tunnel set (`TUNNELS_JSON`) and publishing ports dynamically. `restart: "no"` so a bare `compose up` doesn't loop. |
| **fleet agent** | separate binary in `agent/`, shipped via GitHub Releases | runs on *remote* machines | Not a compose service. Enrolls with the panel over mTLS (one-time token), reports CPU/mem/disk + CVE scans (Trivy), applies targeted package fixes, self-updates. Panel side lives in `api/internal/fleet`. See [fleet-agent](./fleet-agent.md). |

Supporting pieces that are not their own containers:

- **WireGuard** itself runs on the **host kernel** (interface `wg0`), managed by the api via `wgctrl` — there is no wireguard container. Health is checked by probing the interface (`main.go:548`).
- The **nftables firewall** is applied to the host by the api (host-networked, `NET_ADMIN`), not a container.
- The **sentinel** plugin (`traefik/plugins-local/src/local/sentinel`) is a Traefik local plugin providing IP filtering, blocklist enforcement, bot/robots blocking, and time-based access — it is the L7 arm of the firewall.

---

## 3. Container topology & networks

Two Docker networks are declared, plus three containers on host networking:

- **`vpn-network`** (`DOCKER_SUBNET`, default `172.18.0.0/24`, gateway `172.18.0.1`): the bridge network with **static IP assignments** so Traefik, ui, headscale, and turbotunnels have predictable addresses. Traefik `172.18.0.2`, headscale `172.18.0.3`, ui `172.18.0.4`, turbotunnels `172.18.0.5`.
- **`socket-proxy-net`** (`172.31.255.0/28`): a deliberately tiny, single-member network holding *only* docker-socket-proxy. It exists purely so Compose never auto-creates a `_default` network that could grab an overlapping `/16` and clash with `vpn-network`. It is **not** marked `internal`, because that would block the published `127.0.0.1:2375` port the api depends on — isolation instead comes from no other container joining it.
- **Host networking**: `api`, `adguard`, and `vpn-router` share the host's network stack. This is what lets the api manage the kernel firewall/WireGuard and lets AdGuard serve DNS on the host.

> Gotcha (documented in `docker-compose.yml:53-58`): because `2375` is published on `127.0.0.1`, *every* host-networked container shares that loopback and can reach the socket proxy — not just `api` but also `adguard` and `vpn-router`. With `EXEC=1` enabled (needed today for the Headscale CLI), a compromise of any host-networked container could exec into the privileged `api`. Mitigated by keeping the AdGuard dashboard bound to localhost; the tracked structural fix is to drop `EXEC=1` by moving Headscale ops to its REST API.

```
                                Internet
                                   │
                          (optional) Cloudflare
                                   │  80 / 443
                     ┌─────────────▼──────────────┐
   host :80/:443/    │          TRAEFIK           │   local plugin: sentinel
   :8080  ───────────│   (vpn-network 172.18.0.2) │   (IP filter / blocklist /
                     │  routers + middlewares      │    robots / time-access)
                     └──┬─────────┬─────────┬──────┘
        host.docker.internal      │         │  http://ui:80
         :API_PORT (8081)         │         └────────────┐
              │                   │ http://headscale:8080 │
   ┌──────────▼───────────┐  ┌────▼────────┐      ┌───────▼──────┐
   │        API           │  │  HEADSCALE  │      │      UI      │
   │ network_mode: host   │  │ 172.18.0.3  │      │  172.18.0.4  │
   │ pid:host, privileged │  │ (Tailnet    │      │ nginx + SPA  │
   │  ┌────────────────┐  │  │  control)   │      └──────────────┘
   │  │ SQLite (WAL)   │  │  └─────────────┘
   │  │ /data          │  │
   │  └────────────────┘  │      ┌──────────────────────────────┐
   │  nftables (host)     │      │  DOCKER-SOCKET-PROXY          │
   │  wgctrl → wg0 (host) │◄─────┤  127.0.0.1:2375 (filtered)    │
   └───┬───────────┬──────┘      │  socket-proxy-net 172.31.255  │
       │           │             └──────────────────────────────┘
   ┌───▼────┐  ┌───▼────────┐    ┌──────────────┐   ┌─────────────────┐
   │ADGUARD │  │TURBOTUNNELS│    │  VPN-ROUTER  │   │  FLEET AGENTS   │
   │host net│  │172.18.0.5  │    │  host net    │   │ remote machines │
   │ DNS :53│  │(created at │    │ subnet router│   │  mTLS → :fleet  │
   └────────┘  │  runtime)  │    │ WG ⇄ Tailnet │   └─────────────────┘
               └────────────┘    └──────────────┘
```

---

## 4. End-to-end request & data flow

### Admin traffic (browser → panel)

1. **Browser → (optional) Cloudflare → Traefik.** The admin panel is reachable at `http://SERVER_IP/`, on the VPN-only `ADMIN_DOMAIN` (default `manage.me`), and optionally a public `SSL_DOMAIN`. When Cloudflare fronts a domain, the real client IP is carried in `CF-Connecting-IP`; the api keeps Cloudflare's edge ranges current so that header is trusted only for requests that genuinely transit Cloudflare (`main.go:93`, `StartCloudflareIPUpdater`).
2. **Traefik routing** (`traefik/dynamic/core.yml`, generated from `dynamic.yml.template`):
   - `PathPrefix('/')` on the admin host/domain → the **ui** service (`http://ui:80`), priority 10.
   - `PathPrefix('/api/') && !PathPrefix('/api/v1')` → the **unified-api** service, priority 100, behind `rate-limit`, `security-headers`, and `sentinel_fw_block` middlewares.
   - Headscale control-plane paths (`/ts2021`, `/machine`, `/key`, `/noise`, `/derp`, `/register`, `/apple`, `/windows`) → **headscale** directly (Tailscale clients need these).
   - `/api/v1` (Headscale's own admin API) is **blocked** to the outside and gated by `sentinel_vpn` (VPN source ranges only) + strict rate limit — all Headscale admin goes through the api's `/api/hs` instead.
   - Unknown hosts and PWA files on non-admin domains are silently dropped (`sentinel_drop`, `catchall-drop`).
3. **Traefik → api over `host.docker.internal`.** The unified-api service points at `http://host.docker.internal:${API_PORT}` (`core.yml:105-108`), resolved via the `extra_hosts: host-gateway` mapping on the Traefik container. This is the key wiring fact: **the api is host-networked, so Traefik cannot reach it by the `api` hostname on the bridge network** — it must go out to the host gateway and back to the published API port. (See MEMORY: "API is host-networked".)
4. **api request pipeline** (`api/internal/router/router.go`): CORS → security headers → logging (with request IDs, secret-path redaction) → body-size limit (10 MB) → rate limit (token bucket per client IP) → **auth**. Auth is allowlist-based: only `/api/setup/*`, `/api/auth/login`, `/api/restart/*` (tunnel rotation), `/api/hook/*` (webhooks), `/health`, and a few exact paths are public; everything else requires a valid bearer session token. If the auth validator is unavailable the panel **fails closed** for protected paths (`router.go:310`).
5. **api → services/DB.** Handlers act on: the shared **SQLite** database (`/data`, WAL mode), the host **nftables** ruleset and **WireGuard** interface, **Headscale** (REST + occasional CLI via the socket proxy), **AdGuard** (config file + API), **Traefik** (rewriting `traefik/dynamic/*.yml`), and **Docker** (via the socket proxy) to manage turbotunnels/containers.

### Non-admin data planes

- **WireGuard**: peers connect on `WG_PORT/udp` (default `51820`) straight to the host kernel; the api programs peers via `wgctrl`.
- **Headscale/Tailnet**: clients use the control-plane routes through Traefik and DERP/STUN (`3478/udp`, direct `8443`).
- **DNS**: AdGuard answers on `:53`; its query log is tailed by the api's log watchers and folded into analytics.
- **turbotunnels**: user-facing forward proxies listen on dynamically published ports on the panel-created container.
- **Fleet**: remote agents connect inbound over mTLS to the api's managed fleet listener (port from Settings, auto-opened in the firewall); the self-extracting installer is served at `GET /agent/{token}` through Traefik/443 (`main.go:657`).

### Internal-only channels (bypass Traefik and auth)

Registered directly on the mux in `main.go`, guarded by refusing proxied requests:

- `/internal/blocklist` — the sentinel plugin fetches the firewall's block list (container-to-container) to enforce L7 IP blocks, including behind Cloudflare via `CF-Connecting-IP`.
- `/internal/l7block` — sentinel POSTs its periodic L7 block counts back for analytics.

---

## 5. Cross-cutting design decisions & invariants

These are the load-bearing principles; violating them tends to either open a leak or lock the operator out.

### Everything is proxied through one unified api
There is a single Go binary and a single `/api/*` surface. Services self-register at boot from `endpoints.json` (`config.IsServiceEnabled`, `r.RegisterService` in `main.go`), and the router builds routes from that config. The UI and every external caller talk only to this API — no service (Headscale, AdGuard, Docker) is exposed directly to clients. Direct Headscale API (`/api/v1`) is explicitly blocked at the proxy. This gives one place for auth, rate limiting, logging, and secret handling. Cross-service coupling is done with injected function pointers (e.g. `settings.RequestFirewallApply`, `traefik.RegenerateDomains`) to avoid import cycles — see [backend](./backend.md).

### Firewall is the gate / zero-leak
The nftables firewall is treated as *the* boundary, not a convenience. Changes are validated with `nft -c` before being applied, and the intent is that nothing reaches a service that the firewall hasn't explicitly permitted. The L7 arm (sentinel) enforces the same block list at Traefik so blocks hold even behind Cloudflare. (See MEMORY: "Firewall is the gate", and [networking & firewall](./networking-firewall.md).)

### Fail-open / never lock yourself out
Safety mechanisms are designed so a failure can't strand the operator:
- The `sentinel_fw_block` middleware is **fail-open**: if the block list can't be fetched, it blocks *no one* (`core.yml:172-182`), so a backend hiccup can't wall off the panel.
- Auth **fails closed** for protected API paths but the login/setup/health paths are always public, so the setup wizard and login can never be locked out (`router.go:304-313`).
- Direct-IP access to the panel stays open until a domain is configured; only then can it be closed down to domain/localhost/VPN.

### VPN-only admin surface
`ADMIN_DOMAIN` (default `manage.me`) is intended to be resolvable/reachable only over the VPN. Headscale's admin API and several sensitive routes are gated by `sentinel_vpn` to VPN source ranges (`127.0.0.1/8`, `100.64.0.0/10`, and RFC1918). The panel can optionally drop public direct-IP access entirely once a domain exists, leaving it reachable only via the domain, localhost, and WireGuard (`nftables/panel_access.go`, `NewPanelAccessTable`).

### Secrets encrypted at rest
Sensitive settings (API keys, tokens, Tailscale authkeys, AdGuard password) are AES-encrypted in SQLite; WireGuard private keys are stripped before storage. Encryption is initialized from `ENCRYPTION_SECRET` early in boot (`main.go:82`), and a weak/non-32-byte key raises a visible warning into the Activity feed. Backups are passphrase-encrypted (AES-256-GCM, PBKDF2). See [security](./security.md).

### Host-networked, privileged api
The api runs `network_mode: host`, `pid: host`, `privileged`, `NET_ADMIN`, mounting `/var/log:ro` and config directories. This is what lets one process manage the kernel firewall, WireGuard, and host telemetry — and it's why Traefik must reach it via `host.docker.internal` rather than a bridge hostname. Docker access is always mediated by the socket proxy, never the raw socket.

### Config-driven, gracefully degrading services
Each subsystem is guarded by `config.IsServiceEnabled(...)`; a service that fails to initialize logs a warning and is skipped rather than crashing the panel (see the `Warning: Failed to initialize ...` pattern throughout `main.go`). Optional pieces (vpn-router, turbotunnels, fleet) are Compose profiles / settings-gated, so a stopped optional add-on is reported absent rather than "down" (`main.go:566`).

---

## 6. Where to go deeper

| Topic | Doc |
|-------|-----|
| Go service structure, boot sequence, dependency-inversion hooks, background goroutines | [backend](./backend.md) |
| Full REST endpoint list, `endpoints.json`, `/api/schema`, WebSocket channels | [api-surface](./api-surface.md) |
| SQLite schema, encryption at rest, rollups/retention | [data-model](./data-model.md) |
| Auth/2FA, CSP, sentinel, secret handling, threat model | [security](./security.md) |
| nftables tables, jails, geo-blocking, VPN ACLs, WireGuard/Headscale routing | [networking & firewall](./networking-firewall.md) |
| Svelte 5 UI, stores, PWA | [frontend](./frontend.md) |
| `manage.sh`, `install.sh`, systemd, `/opt/wire-panel`, `.env` | [deployment](./deployment.md) |
| Fleet CA, enrollment, agent binary, CVE scanning | [fleet-agent](./fleet-agent.md) |
| Recreating the whole system in another language | [rebuild from scratch](./rebuild-from-scratch.md) |

---

*Verified against `docker-compose.yml`, `api/cmd/main.go`, `api/internal/router/router.go`, `traefik/traefik.yml.template`, `traefik/dynamic.yml.template`, `traefik/dynamic/core.yml`, `traefik/dynamic/domains.yml`, `.env.example`, and `README.md` as of the commit on branch `main` (2026-09-06).*
