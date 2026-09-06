# Deployment & Operations

How the Wire Panel stack is installed, run, and operated. Everything is
orchestrated by `docker-compose.yml` + a large `manage.sh`, driven by a single
`.env`. This document is the reference for install methods, the compose
topology, every `manage.sh` command, config generation, and backups.

Related: [architecture.md](architecture.md) · [networking-firewall.md](networking-firewall.md) · [security.md](security.md) · [fleet-agent.md](fleet-agent.md) · [rebuild-from-scratch.md](rebuild-from-scratch.md)

---

## 1. Install methods

There are two shapes of install, both ultimately driven by `manage.sh`:

### a) Managed install to `/opt/wire-panel` (recommended)

`install.sh` (repo root, 62 lines) does a one-line, root install:

```sh
curl -fsSL https://raw.githubusercontent.com/packalyst/wireguard-admin-panel/main/install.sh | sudo bash
```

Flow (`install.sh`):
1. Re-exec under `sudo` if not root (writes `/opt`, `/etc/systemd`, `/usr/local/bin`).
2. Preflight: require `git` and `docker` on PATH.
3. Conflict guard: refuse if `/opt/wire-panel` already exists (never clobber). (`install.sh:36`)
4. `git clone` the repo into `/opt/wire-panel`, `chmod +x manage.sh`, `chmod 750` the dir.
5. Call `./manage.sh install-service` — registers the systemd unit + `wire-panel` CLI (logic lives in `manage.sh` only, not duplicated).
6. If a TTY is present, `exec ./manage.sh` to run first-time interactive setup; if piped (`curl | bash`, no TTY), it stops and tells the operator to run `sudo wire-panel`.

`INSTALL_DIR=/opt/wire-panel` and `REPO=...packalyst/wireguard-admin-panel.git` are hardcoded in `install.sh`.

### b) Plain checkout

Clone anywhere and run `./manage.sh`. This runs the same setup + bring-up but
without systemd/CLI registration. Convert a plain checkout to the managed layout
later with `./manage.sh migrate` (see §4, migrate). In a plain checkout the help
text and messages use `./manage.sh`; in `/opt/wire-panel` they use `wire-panel`
(chosen by `CMD` at `manage.sh:34` based on whether `SCRIPT_DIR == INSTALL_DIR`).

---

## 2. docker-compose.yml

`SCRIPT_DIR` is `cd`'d into at `manage.sh:9-10`, and `docker compose` is always
run from the project root, so relative bind mounts resolve against the checkout.

### Services

| Service | Image / build | Network mode | Notes |
|---|---|---|---|
| `docker-socket-proxy` | `tecnativa/docker-socket-proxy` | `socket-proxy-net` (dedicated) | Filters the Docker API; publishes `127.0.0.1:2375`. |
| `traefik` | `traefik:v3.6` | `vpn-network` (static IP `${TRAEFIK_CONTAINER_IP}`) | Reverse proxy; ports `${HTTP_PORT}:80`, `${HTTPS_PORT}:443`, `${TRAEFIK_PORT}:8080`. |
| `headscale` | `headscale/headscale:0.25` | `vpn-network` (`${HEADSCALE_CONTAINER_IP}`) | Tailscale control plane + embedded DERP. `command: serve`, `cap_add: NET_ADMIN`. |
| `api` | built from `./api` (arg `VERSION`) | **`network_mode: host`, `pid: host`, `privileged: true`** | The unified backend. Reaches Docker via `DOCKER_HOST=tcp://127.0.0.1:2375`. |
| `adguard` | `adguard/adguardhome:latest` | **`network_mode: host`** | DNS + query logging. |
| `ui` | built from `./ui` (`target: production`) | `vpn-network` (`${UI_CONTAINER_IP}`) | Svelte dashboard; Traefik routes `PathPrefix('/')` to it. |
| `vpn-router` | `tailscale/tailscale:latest` | `network_mode: host` | **profile `vpn-router`** — bridges WG ↔ Headscale via subnet routing. |
| `turbotunnels` | built from `./turbotunnels` | `vpn-network` (`${TURBOTUNNELS_CONTAINER_IP}`) | **profile `turbotunnels`** — image only; runtime container is created by the panel via the Docker API. `restart: "no"`. |

Key invariants (from the compose comments — read them, they encode security decisions):

- **`api` is host-networked** and privileged: it manages nftables/WireGuard on the host. Traefik reaches it via `http://host.docker.internal:${API_PORT}` (the `unified-api` service in the dynamic config), **not** the `api` hostname. See [MEMORY: api-is-host-networked].
- **`docker-socket-proxy` isolation** (`docker-compose.yml:49-60`): it sits on a dedicated single-member `socket-proxy-net` purely so Compose never auto-creates a `_default` network that would grab an overlapping `/16` and clash with `vpn-network`. `:2375` is published on `127.0.0.1`, so **every** host-networked container (`api`, `adguard`, `vpn-router`) shares that loopback and can reach it. `EXEC=1` is enabled (needed for the headscale CLI) — a documented risk with a tracked fix (move headscale ops to REST). See [MEMORY: drop-exec-headscale-rest].
- **Socket-proxy permissions** (`docker-compose.yml:20-46`): read ops + start/stop/restart + EXEC + IMAGES enabled; BUILD/COMMIT/NETWORKS/VOLUMES/SECRETS/etc. explicitly `=0`. The panel can create/start/stop containers and pull images but cannot build (that's why `manage.sh` builds add-on images itself — see §5).

### Profiles

`vpn-router` and `turbotunnels` are gated behind compose **profiles**, so a plain
`docker compose up -d` skips them. Their images would go stale on update, so
`manage.sh` explicitly builds them every deploy (§5) but does **not** start them —
the panel owns their lifecycle (creates the real containers via the Docker API,
injecting runtime config from the encrypted DB). A running add-on picks up a new
image only when restarted from the UI.

### The `api_data` named volume + the folder-name gotcha

```yaml
volumes:
  api_data:      # holds /data → the SQLite DB (app.db) + all panel state
```

`api_data` is the **only** project-scoped Docker volume (compose networks have
fixed `name:` values). Docker prefixes it with the compose project name:
`<project>_api_data`. The project name defaults to the **folder name** unless
`COMPOSE_PROJECT_NAME` is set.

**Gotcha:** `.env.example` pins `COMPOSE_PROJECT_NAME=wire-panel` (`.env.example:7`)
precisely so the volume/network names don't depend on the folder name. Renaming
the folder or changing `COMPOSE_PROJECT_NAME` on an existing install **orphans
the `api_data` volume (your database)**. Never change it on an existing install.
The `migrate` command (§4) copy-renames this volume when moving to `/opt`.

### The `x-logging` anchor

```yaml
x-logging: &default-logging
  driver: json-file
  options:
    max-size: ${DOCKER_LOG_MAX_SIZE:-10m}
    max-file: ${DOCKER_LOG_MAX_FILE:-3}
```

Every service references `logging: *default-logging` so container logs are bounded
(default 10m × 3 files). Tunables are `DOCKER_LOG_MAX_SIZE` / `DOCKER_LOG_MAX_FILE`
in `.env`. (Panel-created containers set their own bounded logging — see the recent
commit "bound logs on panel-created containers".)

### Networks

- `vpn-network` — fixed name, IPAM subnet `${DOCKER_SUBNET}` / gateway `${DOCKER_GATEWAY}` (default `172.18.0.0/24`). Static container IPs are assigned from `.env`.
- `socket-proxy-net` — fixed name, pinned tiny subnet `172.31.255.0/28`. **Not** marked `internal` (that would block the published `127.0.0.1:2375` port the api relies on).

### Dev override

`docker-compose.dev.yml` overrides `ui` to `target: development` with source bind
mounts + `npm run dev`. Activated when `DEV_MODE=true` (set interactively in
`manage.sh` around line 1994), which makes the bring-up use
`-f docker-compose.yml -f docker-compose.dev.yml`.

---

## 3. .env and .env.example

`.env` is the single source of truth; the whole stack (compose + config
generation) is `.env`-driven. `manage.sh` creates it from `.env.example` on first
run if absent (`manage.sh:1786-1795`), then `set -a; source .env` to export
everything for `envsubst` and compose.

Notable groups in `.env.example` (see the file for the full annotated list):

- **Deployment**: `COMPOSE_PROJECT_NAME=wire-panel` (do not change — see gotcha above).
- **Server**: `SERVER_IP` (public IP; used by Headscale/WG/DERP/routing rules).
- **Ports**: `HTTP_PORT` 80, `HTTPS_PORT` 443, `TRAEFIK_PORT` 8080, `API_PORT` 8081, `ADGUARD_PORT` 8083, `HEADSCALE_INTERNAL_PORT` 8085, `STUN_PORT` 3478, `WG_PORT` 51820, `DNS_PORT` 53.
- **WireGuard**: `WG_INTERFACE=wg0`, `WG_IP_RANGE=10.8.0.0/16`, `WG_SERVER_IP=10.8.0.1`, `WG_DNS`.
- **Headscale**: `HEADSCALE_IP_RANGE=100.64.0.0/16`, `HEADSCALE_BASE_DOMAIN=vpn.local`, metrics/grpc ports, DERP region settings.
- **AdGuard**: `ADGUARD_USER`, `ADGUARD_PASS_HASH` (bcrypt; auto-generated on first install — see §6), query/stats retention.
- **SSL**: `SSL_ENABLED`, `SSL_DOMAIN`, `LETSENCRYPT_EMAIL`, `CF_WILDCARD_ENABLED`, `CF_API_EMAIL`, `CF_DNS_API_TOKEN`.
- **Networks**: `IGNORE_NETWORKS` (private ranges the firewall ignores + the VPN-only middleware allows), `DOCKER_SUBNET`/`DOCKER_GATEWAY`, static container IPs, `TRAEFIK_API`.
- **Security**: `ENCRYPTION_SECRET` (REQUIRED), `TRUSTED_PROXIES`.
- **Rate limiting**: `RATE_LIMIT_*` (normal + strict).
- **Logs**: `TRAEFIK_LOGS`/`TRAEFIK_MAIN_LOG`/`ADGUARD_LOGS`/`KERN_LOG` paths, storage limits, GeoIP enrichment, log rotation.
- **Turbotunnels**: `PROXY_DOMAIN` + rotation rate-limit knobs.

### ENCRYPTION_SECRET

The at-rest secret key for the whole panel (AES-256-GCM, via `api/internal/helper`).
Generated with `openssl rand -hex 32`:

- Manually: the `.env.example` comment says `openssl rand -hex 32`.
- Automatically: on setup, if `.env` has no non-empty `ENCRYPTION_SECRET`, `manage.sh` generates one and writes it (`manage.sh:1797-1802`).

Rotate it safely with `manage.sh rotate-key` (§4). It also seeds the fleet CA key
and every DB-stored secret — losing it makes those unrecoverable.

`update_env_value KEY VALUE` (`manage.sh:511-524`) is the one helper for editing
`.env`: it sed-replaces `^KEY=` in place (escaping `& / \ |`) or appends the line
if absent. Every command that mutates `.env` goes through it.

---

## 4. manage.sh — structure & commands

`manage.sh` (~3000 lines) is both a CLI and an interactive menu. Structure:

- **Header** (`:1-110`): `set -e`, `cd $SCRIPT_DIR`, color vars (`RED/GREEN/YELLOW/BLUE/CYAN/NC`), managed-install constants (`INSTALL_DIR`, `PROJECT_NAME`, `SYSTEMD_UNIT=/etc/systemd/system/wire-panel.service`, `CLI_WRAPPER=/usr/local/bin/wire-panel`), `REBUILD_MODE=false`, and `CMD` (display name).
- **Dispatch** (`case "${1:-}"`, `:44-110`): maps a subcommand to a `RUN_*=true` flag (or handles `help`/`rebuild` inline). The flags are acted on later, after the helper functions are defined (`:1259-1318`), because those functions live below the dispatch.
- **Helper/colored output**: `check_dependency`, `prompt_yes_no`, box-drawing status panels throughout. All user-facing output is colored via the vars above; tool output goes to the operator, not the user.
- **`reexec_as_root <subcmd>`** (`:533-538`): re-runs `manage.sh <subcmd>` under `sudo` for privileged paths (writing `/opt`, `/etc/systemd`, `/usr/local/bin`) so they can't half-apply. Called at the top of `migrate`, `rotate-key`, `install-service`.
- **First-install guards**: config regeneration is guarded so re-runs don't clobber stateful files — AdGuard config and the Traefik dashboard toggle are *preserved*, others *regenerated* (§5).

### Command reference

Run as `wire-panel <cmd>` (managed) or `./manage.sh <cmd>` (checkout). Most need Docker/root.

| Command | What it does |
|---|---|
| *(none)* | **Interactive menu** (if the stack is already up) or **first-time setup** (if not). |
| `start` | `docker compose up -d` (`:1295`). |
| `stop` | `docker compose down` (`:1300`). |
| `restart` | `docker compose restart` (`:1305`). |
| `status` | `show_services` — one colored status line per service (`:1310`, `show_services` at `:696`). |
| `logs` | `docker compose logs -f` (all services) (`:1315`). |
| `update` | `check_for_updates` — git-based updater (see below) (`:1259`). |
| `backup` | `backup_certificates` — back up SSL certs (§7) (`:1264`). |
| `rebuild` | Non-interactive: regenerate configs from saved `.env` + rebuild, no prompts (`REBUILD_MODE=true`). |
| `rotate-key` | Re-encrypt all secrets under a fresh `ENCRYPTION_SECRET` (see below) (`:1289`). |
| `migrate` | Move a checkout to `/opt/wire-panel` + register the service (checkout only) (`:1284`). |
| `install-service` | Install/refresh the systemd unit + `wire-panel` CLI (used by `install.sh`) (`:1279`). |
| `service-up` / `service-down` | Non-interactive lifecycle hooks the systemd unit calls (`:1269-1277`). |
| `help` | Usage list (`:54-72`). |

### Interactive menu (stack already up)

Shown when `docker compose ps` reports running containers and `REBUILD_MODE` is
off (`:1331-1443`). Options:

1. **Restart** — bounce all containers.
2. **Rebuild** — sets `REBUILD_MODE=true` and falls through to config regen + `up -d --build`.
3. **Reconfigure** — `docker compose down`, then run the interactive setup Q&A.
4. **Stop** — `docker compose down`, exit.
5. **Update** — `check_for_updates`.
6. **Backup** — `backup_certificates`.
7. **Logs** — submenu picks all / ui / api / traefik / headscale / adguard.
8. **Clean** — **destructive**: `docker compose down -v --rmi all --remove-orphans`, remove generated configs (`headscale/config.yaml`, `traefik/traefik.yml`, `traefik/dynamic.yml`, `acme.json`, `AdGuardHome.yaml`), wipe data dirs, and delete the app's nftables tables (`inet wgadmin_firewall`, `inet wgadmin_vpn_acl`).
9. **Exit**.

### Lifecycle helpers

`service_up`/`service_down` (`:570-578`) just `cd $INSTALL_DIR && docker compose up -d`/`down`. They are what `deploy/wire-panel.service` calls, so compose reads `COMPOSE_PROJECT_NAME` + vars from `.env` in `/opt/wire-panel`.

### `install-service` / systemd / CLI wrapper

`install_service` (`:562-566`) → `reexec_as_root` then:
- `install_systemd_unit` (`:542-549`): copy `deploy/wire-panel.service` → `/etc/systemd/system/`, `daemon-reload`, `systemctl enable`.
- `install_cli_wrapper` (`:553-558`): copy `deploy/wire-panel` → `/usr/local/bin/wire-panel`, `chmod 755`.

`deploy/wire-panel.service` is a **`Type=oneshot` + `RemainAfterExit=yes`** unit
(models "the stack is up" without supervising a pid, since containers are
`restart: unless-stopped`). `ExecStart=manage.sh service-up`,
`ExecStop=manage.sh service-down`, `WorkingDirectory=/opt/wire-panel`,
`TimeoutStartSec=0` (first boot may build images), `Requires=docker.service`,
`WantedBy=multi-user.target`.

`deploy/wire-panel` is a 1-line wrapper: `exec /opt/wire-panel/manage.sh "$@"` —
so `sudo wire-panel <cmd>` == `sudo /opt/wire-panel/manage.sh <cmd>`.

### migrate (checkout → /opt, with volume copy-rename)

`migrate_to_opt` (`:585-689`) moves a plain checkout to the managed layout. It:
1. `reexec_as_root migrate`; refuse if already at `/opt` or if `/opt/wire-panel` exists.
2. Read the **current** project name from this checkout's `.env` `COMPOSE_PROJECT_NAME` (fallback: folder name), so `old_vol=<old_project>_api_data`, `new_vol=wire-panel_api_data`.
3. `docker compose down`.
4. If the volume name changes, **copy-rename** it: create `new_vol`, `docker run ... alpine cp -a /from/. /to/`, then **verify** `app.db` exists in the copy before proceeding (aborts, leaving the old volume untouched, if not).
5. `mv $SCRIPT_DIR /opt/wire-panel`, then **`chown -R root:root` + `chmod 750`** the tree (so a non-root user can't edit a root-executed script — privilege-escalation guard) and `chmod 600 .env`.
6. `update_env_value COMPOSE_PROJECT_NAME wire-panel` (pin the name so the folder no longer determines the volume).
7. `install_systemd_unit` + `install_cli_wrapper`, then `systemctl start wire-panel.service`.
8. Verify the **`api`** container is up (gates the old-volume delete specifically on the DB-consuming container, so a partial bring-up can't report success), then `docker volume rm old_vol`. If unhealthy, the old volume is **kept** for investigation.

This is why the volume rename + the `root:root`/`600` ownership changes matter:
the DB must follow the move, and the tree must be root-owned once systemd runs it.

### rotate-key (re-encrypt all secrets)

`rotate_key` (`:732-813`) rotates `ENCRYPTION_SECRET` with all-or-nothing safety.
Steps (7 phases, each logged):
1. Stop `api` for exclusive DB access.
2. Full DB backup → `backups/rekey-<ts>/` (kept until the operator confirms; `chmod 700`), plus the old key saved as `old-key.txt` (`chmod 600`).
3–4. `docker compose run ... api --rekey` with `ENCRYPTION_SECRET` (old) + `ENCRYPTION_SECRET_NEW` (new `openssl rand -hex 32`) — the re-encrypt is one atomic transaction in the Go binary. On failure: DB unchanged, key **not** swapped, api restarted.
5. Swap the key in `.env` via `update_env_value`, `chmod 600 .env`.
6. `docker compose up -d`.
7. Verify with `api --rekey-check` under the new key. On failure: **automatic rollback** — restore the backup DB, revert the key, restart.

On success it offers to delete the backup (which holds the old key). See
[MEMORY: rotate encryption key] and the `api/internal/rekey` package.

### update (git-based)

`check_for_updates` (`:905-1101`): `git fetch` the current branch, compare local
vs remote commit, list the commits behind with changed files, let the operator
pick a target. `perform_update` (`:1103-1253`) then:
- If the working tree is dirty, offer stash / discard / keep / cancel.
- **Back up SSL certs** before touching anything (`backup_certificates`).
- `docker compose down`, `git merge <target>` (with a conflict resolver: abort / accept theirs / keep ours), restore the stash if used.
- Offer to rebuild → `exec "$0" rebuild` (regenerate configs + rebuild from saved `.env`).

Older installs refresh the host logrotate config on the next `update` (migrate notes this).

### rebuild mode

`REBUILD_MODE=true` (via `rebuild`, menu option 2, or the post-update rebuild)
skips **all** interactive steps (host-conflict checks + the setup Q&A) and reuses
the answers already in `.env` (`:1538-1550` sources `.env`, drops positional
args). Config generation + bring-up below are fully `.env`-driven, so it
reproduces the exact same stack without re-prompting or touching external DNS.

---

## 5. Config generation from *.template (envsubst)

After setup (or in rebuild mode), `manage.sh` regenerates service configs by
substituting `.env` vars into `*.template` files with `envsubst`. Templates found:

| Template | Output | Regenerated vs preserved |
|---|---|---|
| `traefik/traefik.yml.template` | `traefik/traefik.yml` | **Regenerated** every run — but the `api.dashboard` toggle value is read from the existing file first and preserved (`:2598-2603`). When `SSL_ENABLED=true`, the static config is written by a heredoc instead (with live-fetched Cloudflare trusted-IP ranges, a `letsencrypt` HTTP-challenge resolver, and an optional `letsencrypt-dnschallenge` Cloudflare DNS resolver) (`:2605-2706`). |
| `traefik/dynamic.yml.template` | `traefik/dynamic/core.yml` | **Regenerated.** `IGNORE_NETWORKS` is expanded into the `VPN_SOURCE_RANGE` YAML list used by the `sentinel_vpn*` middlewares. When SSL is on, `traefik/dynamic-ssl-routers.yml.template` is rendered and inserted before `services:` (via awk); a `PROXY_DOMAIN` block for rotation/webhook triggers is appended if set (`:2708-2803`). |
| `traefik/dynamic-ssl-routers.yml.template` | (merged into `core.yml`) | Rendered only when `SSL_ENABLED=true`. |
| `headscale/config/config.yaml.template` | `headscale/config/config.yaml` | **Regenerated.** `HEADSCALE_PUBLIC_URL`/`HEADSCALE_HOSTNAME` set to `https://SSL_DOMAIN` or `http://SERVER_IP` depending on SSL (`:2579-2590`). |
| `adguard/conf/AdGuardHome.yaml.template` | `adguard/conf/AdGuardHome.yaml` | **PRESERVED after first install** — only generated when the output file does not exist (`:2808-2815`). It holds DNS rewrites, filter states, the password hash, query-log settings — all of which must survive re-runs. Log line: `· preserved`. |
| `traefik/logrotate.conf` (no `.template` ext) | `/etc/logrotate.d/wgadmin-traefik` | **Regenerated** each run via `envsubst | sudo tee` (`:2817-2827`). Host logrotate for the Traefik `*.log` files (daily, `rotate`/`size` from `.env`, `copytruncate`). |

Additional generated-but-not-templated files:
- `traefik/dynamic/domains.yml` — placeholder created if missing (`# managed by API`); the api owns it thereafter.
- `traefik/acme.json` — created `chmod 600` if missing (Let's Encrypt storage).

**Rule of thumb:** stateful, user/panel-edited files (`AdGuardHome.yaml`,
`traefik/traefik.yml`'s dashboard flag, `domains.yml`, `acme.json`) are preserved;
pure derived files are regenerated. This is why a `rebuild`/reconfigure never
resets the AdGuard admin password or the dashboard toggle.

### Bring-up

`PANEL_VERSION=$(git describe --tags --always --dirty)` is exported and baked into
the api binary via the `VERSION` build-arg (shown on the About page) (`:2835-2840`).
Then `docker compose up -d --build` (plus the dev override if `DEV_MODE=true`).

**Add-on images**: because `docker-socket-proxy` disables BUILD, the panel can't
build the profile images. So after the main bring-up, `manage.sh` runs
`docker compose --profile turbotunnels --profile vpn-router build turbotunnels vpn-router`
to keep them in sync — **without** starting them (the panel owns their lifecycle)
(`:2854-2874`).

If `SSL_ENABLED`, it polls for the Let's Encrypt cert (90s), reports rate-limit /
error / success, and backs up the new cert (§7).

---

## 6. First-install AdGuard credentials

On first install only (`AdGuardHome.yaml` absent), `manage.sh` generates a random
16-char AdGuard password (`:2438-2469`), bcrypt-hashes it (via `htpasswd` or
`python3 bcrypt`), and:
- injects the hash into `AdGuardHome.yaml` via the one-time `envsubst` (the plaintext hash is **never** persisted to `.env`; `AdGuardHome.yaml` is the source of truth thereafter);
- writes the **plaintext** to `adguard/conf/.password.bootstrap` (`chmod 600`) — the single hop by which `wgap-api` picks it up on first boot, encrypts it into its settings DB, then deletes the file;
- prints the credentials once at the end of setup (`:2987-2999`).

---

## 7. Backups

Two independent backup mechanisms exist — do not confuse them:

### a) SSL certificate backup (manage.sh)

`CERT_BACKUP_DIR=/usr/local/wgadmin/certs` (`manage.sh:332`). Functions
`backup_certificates`/`backup_certificate`/`restore_certificate`/`check_certificate_backup`
(`:336-448`) snapshot `traefik/acme.json` (only if it actually contains
certificates, verified with `jq`). Backups are timestamped
(`acme_<domain>_<ts>.json`, `chmod 600`) with an `acme_<domain>_latest.json`
symlink, under a `chmod 700` dir. Triggered by: `manage.sh backup`, menu option 6,
automatically before every `update` (`perform_update`), and automatically after a
successful post-deploy cert issuance. `restore_certificate` is used on setup when
`RESTORE_FROM_BACKUP=true`. `check_cert_rate_limit` queries crt.sh to warn about
Let's Encrypt's 5-duplicate-certs-per-7-days limit.

### b) Settings encrypted backup (panel app feature)

Separate from `manage.sh`: the panel exposes a **passphrase-encrypted backup** of
its own configuration (`api/internal/backup`, routes under `/api/backup`, UI in
`SettingsView.svelte`):
- `POST /api/backup/export {passphrase, users, fleet}` → streams a
  `wire-panel-<ts>.wgbackup` download (passphrase-sealed; `MinPassphrase` enforced).
- `POST /api/backup/preview {passphrase, backup}` → decrypts and reports what an import *would* do (no writes).
- `POST /api/backup/import {passphrase, backup, confirm}` → faithful replace, then `Reconcile()` re-applies live state (nftables, WireGuard, ACLs, fleet listener) and reports the touched subsystems.

This is a portable panel-config backup/migrate feature (session-gated, like the
rest of the panel API); the SSL cert backup above is the ops-level cert safety
net. See [data-model.md](data-model.md) / [api-surface.md](api-surface.md) for the
backup document format and endpoint details.

---

## 8. Dependency handling

Setup checks for `docker`, `docker compose`, `envsubst` (gettext), `curl`, and the
WireGuard kernel module / `wg` (`:1450-1531`), and offers to install missing ones
(`install_docker`, `install_wireguard`, apt/yum for gettext/curl). It also frees
port 53 (offers to disable `systemd-resolved`) and checks for Docker subnet
conflicts before bring-up (`check_subnet_conflict`, `:1816`).

---

## Unverified / flagged

- The `.env` file present on disk was not read (only `.env.example`); the documented `.env` contents describe the template.
- `install_docker` / `install_wireguard` bodies (`:828-904`) were only partially read; they branch on Debian/RedHat as expected but the exact package steps weren't fully transcribed.
- The `api --rekey` / `--rekey-check` internals live in `api/internal/rekey` (referenced by `rotate_key`) and are documented in [data-model.md](data-model.md)/[security.md](security.md), not here.
