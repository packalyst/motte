# Rebuild From Scratch

> A sequenced guide to reimplement this system in **any** stack. It says *what to build, in
> what order, and which contracts and invariants must hold* — it does not repeat the detail
> in the sibling docs, it points at them.

**Siblings:** [README](./README.md) · [architecture](./architecture.md) ·
[backend](./backend.md) · [api-surface](./api-surface.md) · [data-model](./data-model.md) ·
[security](./security.md) · [networking-firewall](./networking-firewall.md) ·
[frontend](./frontend.md) · [deployment](./deployment.md) · [fleet-agent](./fleet-agent.md) ·
[coding-standards](./coding-standards.md)

---

## 0. What you are building

A self-hosted admin panel that manages a WireGuard + Headscale VPN, a host-level nftables
firewall (IP/CIDR/country/ASN blocking, VPN ACLs, per-peer egress control), a Traefik reverse
proxy fronting everything, AdGuard Home for DNS filtering, and an optional fleet of
per-machine security agents. The panel is a single Go binary today; you may reimplement it in
any language provided the **contracts** ([§3](#3-the-contracts-between-components)) and
**security invariants** ([§4](#4-security-invariants-that-must-hold)) below are preserved.

The whole system runs as a Docker Compose stack plus one **host-networked** application
process. Reproduce that topology conceptually even if your language/orchestrator differs.

---

## 1. Build order (dependency-first)

Build bottom-up; each layer is testable before the next exists.

### Phase A — Foundations (no HTTP yet)
1. **Config loader** — endpoints/services are data-driven from a config file, not hardcoded
   routes (today `config.Load`, `api/internal/config`). Decide this early: the router is
   built from config × registered handlers (see [backend](./backend.md)).
2. **Database + migrations** — SQLite today (`api/internal/database`, `database.Init`).
   Schema and the encrypted-column list are in [data-model](./data-model.md). Establish
   `GetDB()`-style shared access.
3. **Encryption-at-rest** — AES-256-GCM with a single key-derivation rule
   (`ParseKey`: 32-byte hex → key; else SHA-256 + weak flag). Random nonce prepended,
   base64. Build `Encrypt/Decrypt` + `EncryptWith/DecryptWith` first — everything with
   secrets depends on it. See [security](./security.md) and
   [coding-standards §3.3](./coding-standards.md#33-secrets-encrypted-at-rest-one-derivation-atomic-rotation).
4. **Key rotation tool** — a one-shot that decrypts every secret with the old key, then
   re-encrypts all in one transaction under the new key, plus a verify-only mode. This is a
   *foundation*, not an afterthought: the encrypted-column inventory must be complete from day
   one or rotation silently misses columns.

### Phase B — The gate (firewall)
5. **nftables script builders** — pure functions that emit validated nft text: identifier/
   family/set-type/hook/policy validators, element sanitizers, IPv4-only boundary validator,
   `BuildSet`/`BuildChain`/`TableHeader`. Unit-test these against `nft -c`.
6. **nftables apply service** — atomic apply (`delete table` + recreate in one `nft -f`),
   debounced (~500ms), with a broadcast hook for status. Registers pluggable "tables."
7. **The tables**: main firewall (IP/range/country/ASN block + allow, port allow-list, MSS
   clamp, per-peer WAN egress, IPv6-leak drop), VPN ACL (peer isolation, default-deny),
   panel-access (close the API port to the public), cloudflare-only (lock 80/443 to CF edge).
   Fail-open rules per [§4](#4-security-invariants-that-must-hold). Full runtime model in
   [networking-firewall](./networking-firewall.md).

### Phase C — HTTP core
8. **Router + middleware chain** — auth (fail-closed), CORS, body-size limit, rate limiting,
   security headers/CSP, logging. Config-driven route registration. JSON helpers
   (`JSON`, `JSONError`, `DecodeJSONOrError`). See [api-surface](./api-surface.md).
9. **Auth service** — session tokens, TOTP, setup wizard (first-run), PWA push. Register
   first; other services depend on it.
10. **WebSocket hub + broadcaster** — pub/sub channels (`general_info`, server stats,
    firewall status, activity). The nftables/service broadcast hook wires into this.
11. **Events / activity log** — append-only, capped table; used to surface warnings
    (e.g. weak encryption key) to operators.

### Phase D — Domain services
12. **WireGuard** — peer CRUD, key generation, encrypted key storage, config/QR download,
    interface + session management, virtual IPs. (service/handlers/store split.)
13. **Headscale** integration (auth keys, ACLs, nodes), **AdGuard** integration,
    **Traefik** config generation, **domains**, **turbotunnels** (SMS-style pass-through /
    rotation / webhooks), **server stats**, **logs** (source watchers: traefik, adguard,
    outbound, conntrack), **geolocation** (country/ASN → CIDR provider for the firewall),
    **backup & migrate** (passphrase-encrypted export/import).

### Phase E — Fleet (optional, last)
14. **Fleet CA + enrollment endpoint** on the panel, then the **per-machine agent**
    (metrics, sub-agent supervision, nftables enforcement, mTLS to the panel). See
    [fleet-agent](./fleet-agent.md).

### Phase F — Frontend & delivery
15. **SPA** (Svelte 5 runes today) talking to the API via one auth-injecting client;
    strict CSP, no inline scripts. See [frontend](./frontend.md).
16. **Compose stack + `manage.sh`-equivalent** operator CLI and managed install. See
    [deployment](./deployment.md).

---

## 2. Runtime topology

```
Internet
   │
   ▼
[Traefik]  ── proxies ──►  http://host.docker.internal:${API_PORT}  ──►  [API]  (host-networked)
   │  (CSP, VPN-only sentinel, rate-limit, L7 block-list, TLS/ACME)         │
   │                                                                        ├─► SQLite (encrypted secrets)
   ├─► [UI static]                                                          ├─► nftables (host, via NET_ADMIN)
   │                                                                        ├─► WebSocket (to browser)
[headscale] [adguard] [vpn-router(tailscale)] [turbotunnels]               └─► docker-socket-proxy ─► dockerd
   │
[docker-socket-proxy] ── least-privilege ──► /var/run/docker.sock
```

- The **API is host-networked** (`network_mode: host`, `cap_add: NET_ADMIN`) so it can drive
  nftables and bind host ports. It is therefore **not** on the Docker bridge and is reachable
  from Traefik only via the `host.docker.internal → host-gateway` mapping.
- Traefik, headscale, adguard, vpn-router each run with the capabilities they need
  (`NET_ADMIN` where they touch networking); adguard and vpn-router are also host-networked.
- Compose services and every panel-created container use **bounded** json-file logging.

---

## 3. The contracts between components

Reimplement these exactly; they are the seams that let you swap any single component.

| Seam | Contract | Authority in code |
|------|----------|-------------------|
| **Traefik → API** | HTTP to `http://host.docker.internal:${API_PORT}`. Compose maps `host.docker.internal:host-gateway`. Never an `api` bridge hostname. | `traefik/dynamic.yml.template:108`, `traefik/traefik.go:1320`, `docker-compose.yml:85` |
| **Traefik → API (L7 controls)** | Traefik's sentinel plugin pulls the block-list from `/internal/blocklist` and reports blocks to `/internal/l7block` on the same host URL; **fail-open** if unreachable. | `traefik/dynamic.yml.template:176-181` |
| **API → DB** | SQLite via a shared handle (`GetDB()`); secrets stored in `*_enc` columns / `settings.encrypted=1`; all queries parameterized. | `api/internal/database`, [data-model](./data-model.md) |
| **API → nftables** | API renders validated nft text and applies it atomically with `nft -f` (`delete table` + recreate); debounced; requires host net + `NET_ADMIN`. | `api/internal/nftables` |
| **API → browser (WS)** | WebSocket pub/sub; server pushes `general_info`, firewall status, stats, activity events on named channels. | `api/internal/ws`, `nftables/service.go:66-76` |
| **API → Docker** | Only through `docker-socket-proxy` with explicit capability flags (`CONTAINERS/INFO/POST/ALLOW_*/IMAGES` on; `NETWORKS/VOLUMES` off). Container names validated before use in the API path. | `docker-compose.yml:12-44`, `helper/docker_client.go` |
| **API → external URLs** | All operator-influenced fetches use an SSRF-guarded client validating the *resolved* IP at dial time. | `helper/safehttp.go` |
| **Agent ↔ Panel** | Enrollment: agent generates an EC keypair locally (key never leaves host), builds a CSR, POSTs it with a one-time token, pins the panel CA by fingerprint. Steady state: outbound **mTLS** (client cert + key vs. stored CA, TLS ≥1.2); agent pushes reports, pulls+executes commands. | `agent/register.go`, `agent/panel.go:19-56` |
| **Env → all** | `.env` is the single config surface; keys are only ever written via an escaping `update_env_value`-style function; fallbacks match `.env.example`. | `manage.sh:511-524`, `.env.example` |

---

## 4. Security invariants that MUST hold

These are the product. A reimplementation that omits any of them is wrong regardless of
feature parity. Detail and rationale live in [security](./security.md),
[networking-firewall](./networking-firewall.md), and
[coding-standards §3](./coding-standards.md#3-security-first-rules-the-non-negotiables).

1. **Firewall is the gate, and it fails OPEN for the admin path.** Any table that *restricts*
   access to the management plane (panel-access, cloudflare-only) must emit an empty
   (no-op) table whenever it can't fully trust its inputs, and must always keep loopback +
   Docker + WG + Headscale ranges trusted. Never risk locking the operator out.
   *Exception:* IPv6-leak controls fail **closed** — an undetected WAN drops IPv6 rather than
   leaking it. Leaks close; lockouts open.
2. **Validate every nftables change before it can take effect.** Every element passes a
   boundary validator at build time (IPv4-only, valid port, valid identifier); an invalid
   element must be skipped, never emitted, because the atomic reload would otherwise wedge the
   whole table (for the VPN ACL that silently flips default-deny → default-allow). Lint dumped
   scripts with `nft -c`.
3. **Secrets encrypted at rest with one derivation + atomic rotation.** AES-256-GCM; a single
   `ParseKey` rule shared by the live process and the rotation tool; rotation is
   all-or-nothing in one transaction with pre-flight decrypt, post-swap verify, and rollback.
   The encrypted-column inventory must be complete.
4. **VPN-only / authenticated admin plane, fail-closed auth.** A missing/failed auth validator
   returns 503 for protected paths; only an explicit small allowlist is public. Admin reaches
   the panel via the domain through Traefik (VPN-only sentinel, rate-limit, ban-list), not the
   raw API port once a domain is configured.
5. **CSP with no inline scripts.** API responds `default-src 'none'`; the UI is served under
   strict `script-src 'self'`. The SPA carries zero inline scripts/handlers; dynamic images
   are `data:` URLs. This is the XSS backstop — do not weaken it.
6. **Least-privilege Docker.** No raw socket mount; a capability-scoped proxy only.
7. **SSRF-safe outbound fetches** for any operator-supplied URL (blocklists, webhooks),
   blocking private/CGNAT/reserved ranges at dial time.

---

## 5. External dependencies

You do not reimplement these — you integrate them (versions pinned in `docker-compose.yml`):

| Dependency | Role | Notes |
|------------|------|-------|
| **WireGuard** (`wgctrl`) | the VPN data plane | kernel module + `wg0`; keys generated & stored encrypted by the panel |
| **Headscale** (0.25) | self-hosted Tailscale control server | auth keys, ACLs, nodes; some ops still via its CLI (proxy `EXEC=1`), migrating to REST |
| **Tailscale** (`vpn-router`) | overlay routing node | host-networked, `NET_ADMIN` |
| **AdGuard Home** | DNS filtering / query logs | host-networked; a log source watcher |
| **Traefik** (v3.6) | reverse proxy, TLS/ACME, CSP, VPN-only + rate-limit + L7 block sentinel | dynamic config generated by the panel |
| **Trivy / CrowdSec / osquery** | fleet-agent sub-agents (CVE scan, IPS, host queries) | installed & supervised by the agent |
| **docker-socket-proxy** (tecnativa) | least-privilege Docker API | capability-flag gated |
| **SQLite** (`mattn/go-sqlite3`) | persistence | single-file DB, encrypted secret columns |

---

## 6. Rebuild checklist

**Foundations**
- [ ] Config-driven service/endpoint registration (not hardcoded routes).
- [ ] SQLite schema + migrations; `*_enc` columns for every secret ([data-model](./data-model.md)).
- [ ] AES-256-GCM `Encrypt/Decrypt` with a single `ParseKey` derivation; weak-key warning surfaced to the activity feed.
- [ ] Atomic key-rotation tool (rekey + verify + rollback) with a complete encrypted-column inventory.

**Firewall (the gate)**
- [ ] nft builders with identifier/family/type/hook/policy validation + element sanitizers + IPv4-only boundary guard.
- [ ] Atomic, debounced apply (`delete table` + `nft -f`), status broadcast.
- [ ] Tables: main firewall, VPN ACL (default-deny), panel-access (fail-open), cloudflare-only (fail-open).
- [ ] `nft -c` lint path for dumped scripts; behavior tests pin fail-open + rule ordering.

**HTTP core**
- [ ] Middleware: fail-closed auth, CORS, body-size limit, rate limit, security headers/CSP, logging.
- [ ] JSON + decode helpers; parameterized SQL everywhere.
- [ ] WebSocket hub + broadcaster; events/activity log.
- [ ] Auth (sessions, TOTP, setup wizard, PWA push) registered first.

**Domain services**
- [ ] WireGuard (peers, encrypted keys, config/QR, sessions, virtual IPs).
- [ ] Headscale, AdGuard, Traefik-config, domains, turbotunnels, server stats, logs, geolocation, backup/migrate.

**Topology & security**
- [ ] App is host-networked with `NET_ADMIN`; Traefik reaches it via `host.docker.internal`.
- [ ] Docker access only through the capability-scoped proxy.
- [ ] SSRF-guarded outbound client for operator URLs.
- [ ] Strict CSP, no inline scripts in the SPA; API bearer token injected by one client helper.
- [ ] Bounded logging on all containers, incl. panel-created ones.

**Fleet (optional)**
- [ ] Panel CA + token enrollment endpoint (CSR signing, CA-fingerprint pinning).
- [ ] Agent: local keygen, mTLS, metrics, sub-agent supervision, self nftables enforcement.

**Delivery**
- [ ] Operator CLI: colored output, `.env` mutation via escaping helper, root re-exec for privileged paths, reversible key/DB operations, `bash -n` clean.
- [ ] Compose stack with pinned images; managed install (systemd unit + CLI wrapper).
- [ ] `go test ./...`-equivalent green, including the invariant-pinning tests.

---

## 7. Verification — prove the invariants, not just the features

Before calling a reimplementation done, demonstrate each invariant:

- **Fail-open:** disable/garble the panel-access inputs → the emitted table is an empty shell
  with no `drop`, and the operator still reaches the panel.
- **Atomic firewall:** feed a bad element (IPv6 in an IPv4 set) → it is skipped, the table
  still applies, no rules are lost.
- **Rotation:** rotate the key → every secret decrypts under the new key; a forced mid-rotation
  failure leaves the DB and key unchanged (rollback).
- **Auth fail-closed:** with auth uninitialized, a protected path returns 503, not data.
- **CSP:** an injected `<script>` in any rendered value does not execute.
- **Least-privilege Docker:** a network/volume Docker operation is refused by the proxy.

See [coding-standards §7](./coding-standards.md#7-testing-patterns) for the testing style that
encodes these.
</content>
