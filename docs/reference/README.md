# Reference documentation

This folder is a complete reference for the WireGuard/Headscale admin panel — enough to **recreate the system from scratch in any language**, or to know **exactly where and how to change** any behavior. Every doc is grounded in the actual source and cites concrete `file:line` locations.

## What this project is

A self-hosted, single-operator **VPN admin panel** that unifies a WireGuard/Headscale control plane, an AdGuard DNS resolver, a Traefik reverse proxy, a panel-managed **nftables firewall**, per-peer turbotunnels forward proxies, and a per-machine **fleet agent** (mTLS enrollment + CVE scanning). The backend is Go (`api/`, packages under `api/internal/`), the frontend is Svelte 5 runes (`ui/`), and the whole stack is orchestrated by `docker-compose.yml` and a large `manage.sh` (install / update / rebuild / migrate / rotate-key, plus a systemd-managed install via `install.sh`).

Two invariants run through everything: **the firewall is the gate** (default-drop, fail-open only where a lock-out is possible, validated by construction), and **secrets are encrypted at rest** (AES-256-GCM, with a safe key-rotation path).

## The docs

### Start here
| Doc | What it covers |
|---|---|
| [architecture.md](architecture.md) | The whole system at a glance — components, container topology & networks, the end-to-end request/data flow (browser → Cloudflare → Traefik → api → services), and the cross-cutting design invariants. **Read this first.** |
| [rebuild-from-scratch.md](rebuild-from-scratch.md) | A sequenced, stack-agnostic guide to reimplement the system: build order, the contracts between components, the security invariants that must hold, and a verification checklist. |

### Backend
| Doc | What it covers |
|---|---|
| [backend.md](backend.md) | How the Go backend is organized — the `api/internal` package layout, the `main.go` boot sequence (including the `--rekey` one-shot), the config-driven router/service-registration pattern, the handler/store/service package shape, DB access, the WebSocket hub, and the events feed. |
| [api-surface.md](api-surface.md) | How HTTP endpoints are declared (data-driven `endpoints.json`) and registered, the auth/middleware model, the main route groups per subsystem, the `/internal/*` and `/agent/{token}` routes, and the separate fleet mTLS listener. |
| [data-model.md](data-model.md) | The full SQLite schema table-by-table, the **complete set of encrypted-at-rest columns**, the settings key/value/encrypted pattern, and the migration approach. |

### Cross-cutting concerns
| Doc | What it covers |
|---|---|
| [security.md](security.md) | The application security model — at-rest encryption & the rotate-key flow, human auth (login/sessions/2FA), fleet mTLS, web hardening/CSP & secrets handling, and the L3-vs-L7 access controls. |
| [networking-firewall.md](networking-firewall.md) | The nftables design — the separate tables (`wgadmin_firewall`, `wgadmin_panel_access`, `wgadmin_cf_only`, `wgadmin_vpn_acl`), the set inventory, how ports open, jails, the two L3 access toggles, Cloudflare handling, and the L7 sentinel plugin. |

### Frontend
| Doc | What it covers |
|---|---|
| [frontend.md](frontend.md) | The Svelte 5 runes frontend — directory layout, the path-based router, the app store & API client, the runes conventions actually used, reusable components, charting, the PWA/service worker, and a worked example of adding a settings toggle end-to-end. |

### Operations
| Doc | What it covers |
|---|---|
| [deployment.md](deployment.md) | Install/run/operate — docker-compose services & the `api_data` volume gotcha, `.env`, every `manage.sh` command, config generation from `*.template`, backups, and the systemd-managed install/migrate/rebuild/rotate-key flows. |
| [fleet-agent.md](fleet-agent.md) | The per-machine agent (`agent/`) — what it does, enrollment over mTLS, the reporting/commands loop, uninstall/deregister, the secrets store, and the release process. |

### Contributing
| Doc | What it covers |
|---|---|
| [coding-standards.md](coding-standards.md) | The coding standards & patterns a contributor (or agent) must follow — derived from the code: Go conventions, the nftables sub-discipline, the security-first non-negotiables, DRY / no-dead-code, Svelte runes conventions, `manage.sh` conventions, testing, and commit style. |

## How these docs were produced & their limits

These were written by reading the source directly, with `file:line` citations throughout, and spot-checked against the code (the encrypted-store list, the registered firewall tables, and the access-control behaviors were verified). Where a doc's claim diverged from an assumption, or where a feature is designed-but-not-yet-built, it is **flagged inline** rather than presented as fact — notably:

- The runtime applies nftables via `nft -f` on a temp file (one atomic transaction), **not** a separate `nft -c` pre-flight; safety comes from per-boundary input validation + the atomic apply.
- Header-trust for the real client IP is an **API-side** concern (`TRUSTED_PROXIES` → `GetClientIP`), not `forwardedHeaders.trustedIPs` in the current Traefik template.
- The session token currently lives in `localStorage` (HttpOnly-cookie migration is a tracked follow-up), and the fleet `machineIdentityHash` replay check is stored-but-not-yet-enforced.

Treat each doc as a reviewed reference, and confirm against the cited source before relying on a fine detail.
