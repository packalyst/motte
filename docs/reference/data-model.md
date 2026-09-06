# Data Model

The panel persists everything in a single **SQLite** database. This document
covers every table, why its notable columns exist, the relationships between
tables, and — critically — which columns are **encrypted at rest**.

For how the encryption/rotation actually works (key derivation, the `--rekey`
one-shot, the AES helper), see [security.md](./security.md). For the wider
system layout see [architecture.md](./architecture.md) and
[backend.md](./backend.md); the fleet tables are also described operationally in
[fleet-agent.md](./fleet-agent.md).

---

## Storage, location & pragmas

- **File:** `app.db`, created at `<DATA_DIR>/app.db`.
  `DATA_DIR=/data` in the container and the `api_data` named volume is mounted at
  `/data`, so the DB lives in the `api_data` Docker volume and survives container
  restarts. (`api/internal/database/database.go:63-72`, `docker-compose.yml`
  `DATA_DIR=/data` + `api_data:/data`.)
- **Open DSN:** `app.db?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=1`
  (`database.go:72`).
  - **WAL mode** — concurrent readers don't block the single writer; you will see
    `app.db-wal` / `app.db-shm` sidecar files in the volume.
  - **`_busy_timeout=5000`** — wait up to 5 s on a locked DB before erroring.
  - **`_foreign_keys=1`** — FK enforcement is enabled **per connection**, so the
    schema's `ON DELETE CASCADE` / `SET NULL` clauses actually fire. SQLite
    ignores foreign keys unless this is set. This is why deleting a peer
    (`vpn_clients`) also removes its ACL rows, virtual IPs, and domain-route
    links instead of orphaning them into the firewall (`database.go:67-71`).
- **Timeouts:** the `database.DB` wrapper applies a 30 s context timeout to
  `Exec` (`database.go:20,34-38`). Reads (`Query`/`QueryRow`) use the raw
  `sql.DB` for SQLite compatibility.
- **FK pre-check:** after `createSchema`, `PRAGMA foreign_key_check` runs and
  logs any pre-existing violations loudly (enabling FK does not retroactively
  validate old rows) (`database.go:87-102`).

The schema is created idempotently with `CREATE TABLE IF NOT EXISTS` in
`createSchema` (`database.go:126-536`), grouped into four SQL blocks: firewall,
app, VPN/ACL, logs, and user-PWA. A handful of tables are created lazily by
other packages on first use (see [Dynamically-created tables](#dynamically-created-tables)).

---

## Encrypted-at-rest columns (the complete set)

Secrets are stored ciphertext-only. The authoritative, complete list lives in
the rekey package (`api/internal/rekey/rekey.go:34-42`), which re-encrypts every
one of these under a new key; the `settings` encrypted rows are handled
separately (`rekey.go:109-110`).

| Table | Column(s) | What it holds | Critical? |
|---|---|---|---|
| `vpn_clients` | `private_key_enc` | WireGuard peer private key | yes |
| `vpn_clients` | `preshared_key_enc` | WireGuard peer PSK | yes |
| `users` | `totp_secret_enc` | TOTP/2FA seed | yes |
| `fleet_ca` | `key_enc` | Fleet CA private key (PEM) | yes |
| `users_push_subscriptions` | `key_p256dh` | Web Push ECDH public key | yes |
| `users_push_subscriptions` | `key_auth` | Web Push auth secret | yes |
| `vpn_router_config` | `authkey_enc` | Headscale pre-auth key for the subnet router | **no** — ephemeral, write-only, never read back; a decrypt failure is skipped, not fatal (`rekey.go:41`) |
| `settings` | rows where `encrypted=1` | see [Encrypted settings keys](#encrypted-settings-keys) | yes |

**Convention:** an `_enc` suffix marks an encrypted column. The two Web Push
columns (`key_p256dh`, `key_auth`) are encrypted despite lacking the suffix —
`rekey.go:30-32` calls this out explicitly, and the backup package's list
*omits* them, so they are an easy one to miss.

### Encrypted settings keys

Written via `settings.SetSettingEncrypted` (which sets `encrypted=1`,
`api/internal/settings/settings.go:552-567`) or, for VAPID, a direct
`tx.Exec` with `encrypted=true` (`api/internal/auth/pwa/pwa.go:154`):

| Key | Source | Purpose |
|---|---|---|
| `headscale_api_key` | `setup/setup.go:240,380` | Headscale admin API key |
| `headscale_api_key_pending` | `setup/setup.go:235` | staged API key during setup, before commit |
| `adguard_password` | `settings/settings.go:386` | AdGuard Home admin password |
| `geo_maxmind_license_key` | `geolocation/handlers.go:105` | MaxMind GeoIP license key |
| `geo_ip2location_token` | `geolocation/handlers.go:110` | IP2Location API token |
| `turbotunnels_config` | `turbotunnels/config.go:270` | turbotunnels config blob (JSON) |
| `vapid_private_key` | `auth/pwa/pwa.go:154` | Web Push VAPID private key |

> `vapid_public_key` and `vapid_subject` are stored **unencrypted** (only the
> private half is secret).

---

## Firewall schema
`database.go:128-195`

### `jails`
fail2ban-style log-scanning ban rules.

| Column | Meaning |
|---|---|
| `name` | unique jail name |
| `enabled` | on/off |
| `log_file`, `filter_regex` | what to tail and the match pattern |
| `max_retry`, `find_time` | N failures within `find_time` seconds triggers a ban |
| `ban_time` | ban duration seconds (default `2592000` = 30 days) |
| `port`, `action` | scope + action (`drop`) |
| `last_log_pos` | resume offset so the scanner doesn't re-read the whole log |
| `escalate_enabled`, `escalate_threshold`, `escalate_window` | escalate a repeat offender (e.g. ban the /24) |
| `escalate_asn`, `escalate_asn_threshold`, `escalate_asn_window` | escalate all the way to the offender's whole ASN — separate, wider threshold since a provider is far broader than a subnet (added by migration, see below) |

### `country_zones_cache`
Cached CIDR ranges per country code (`country_code` PK, `zones` TEXT), joined at
firewall-build time so country blocking doesn't re-expand ranges each apply.

### `asn_zones_cache`
Same idea for ASNs: cached IPv4 CIDRs per `asn` (PK), expanded once from the ASN
DB then joined at build time.

### `firewall_entries`
The **unified** firewall table — every manual/auto IP, range, country, ASN, or
port rule.

| Column | Meaning |
|---|---|
| `entry_type` | `ip` \| `range` \| `country` \| `asn` \| `port` (CHECK-constrained) |
| `value` | the address/CIDR/country code/ASN/port |
| `action` | `block` \| `allow` |
| `direction` | `inbound` \| `outbound` \| `both` |
| `protocol` | `tcp` \| `udp` \| `both` |
| `source` | provenance (`manual`, jail name, etc.) |
| `reason`, `name` | free text / label |
| `essential` | protected entry that must not be auto-pruned |
| `expires_at` | auto-ban TTL (NULL = permanent) |
| `enabled`, `hit_count` | toggle + match counter |

Uniqueness is `(entry_type, value, protocol)` (`idx_firewall_entries_unique`),
plus several composite indexes tuned for the firewall-build queries. See
[networking-firewall.md](./networking-firewall.md) for how these rows become
nftables rules.

---

## App schema
`database.go:198-272`

### `users`
Admin accounts.

| Column | Meaning |
|---|---|
| `username` | unique |
| `password_hash` | hashed password |
| `totp_secret_enc` | **encrypted** TOTP seed |
| `totp_enabled` | 2FA on/off |
| `last_login` | last successful auth |

### `settings`
Key-value store — the panel's general config bag.

| Column | Meaning |
|---|---|
| `key` | PK |
| `value` | string value (ciphertext when `encrypted=1`) |
| `encrypted` | `1` ⇒ `value` is AES ciphertext (see [encrypted settings keys](#encrypted-settings-keys)) |
| `updated_at` | last write |

Read/write helpers distinguish the two: `setSetting` writes `encrypted=0`,
`setSettingEncrypted` encrypts then writes `encrypted=1`
(`settings.go:519-567`). Notable non-encrypted keys seen across the codebase:
`headscale_url`, `headscale_api_url`, `adguard_username`, `adguard_pass_changed`,
`session_timeout`, `display_timezone`, `api_direct_access`, `traefik_fw_block`,
`web_cloudflare_only`, `fleet_enabled`, `fleet_port`, `vapid_public_key`,
`vapid_subject`, and the `geo_*` family (`geo_blocking_enabled`,
`geo_lookup_provider`, `geo_auto_update`, `geo_update_hour`, …).

### `events`
One chronological activity feed across all subsystems (blocks, peer changes,
config edits, restarts). `type`, `severity` (default `info`), `subsystem`,
`message`. Retention-capped by the `events` package so it can't grow unbounded
(`database.go:218-229`). Indexed `id DESC` for the "latest N" feed.

### `sessions`
Login tokens.

| Column | Meaning |
|---|---|
| `id` | token (TEXT PK) |
| `user_id` | FK → `users(id)` **ON DELETE CASCADE** |
| `ip_address`, `user_agent` | where the session came from |
| `last_active`, `created_at`, `expires_at` | lifecycle |

> Security note: the token currently lives in the DB and is handed to the client;
> a planned change moves it to an HttpOnly cookie. See [security.md](./security.md).

### `domain_routes`
Traefik reverse-proxy routes managed by the panel.

| Column | Meaning |
|---|---|
| `domain` | unique hostname |
| `target_ip`, `target_port` | backend |
| `vpn_client_id` | FK → `vpn_clients(id)` **ON DELETE SET NULL** (route survives peer deletion, just unlinked) |
| `enabled` | toggle |
| `https_backend` | backend speaks TLS |
| `middlewares` | JSON array of Traefik middleware names (default `[]`) |
| `access_mode` | `vpn` (default) \| `public` |
| `frontend_ssl` | terminate TLS at the edge |
| `cert_resolver` | optional TLS cert-resolver override (added by migration) |
| `sentinel_config` | JSON config for per-domain sentinel middleware (added by migration) |
| `skip_cert_verify` | skip backend TLS verification for HTTPS backends (added by migration) |

See [networking-firewall.md](./networking-firewall.md) / deployment for the
Traefik integration.

---

## VPN / ACL schema
`database.go:275-362`

### `vpn_clients`
Unified view of **all** VPN clients, both WireGuard and Headscale.

| Column | Meaning |
|---|---|
| `name` | display name |
| `ip` | VPN IP, **unique** |
| `type` | `wireguard` \| `headscale` (CHECK) |
| `external_id` | id in the source system (Headscale node id, etc.) |
| `raw_data` | raw JSON from the source system |
| `public_key` | WG public key (plaintext) |
| `private_key_enc` | **encrypted** WG private key |
| `preshared_key_enc` | **encrypted** WG PSK |
| `enabled` | toggle |
| `acl_policy` | `block_all` \| `selected` (default) \| `allow_all` — the peer's default reachability posture |
| `total_tx`/`total_rx`/`last_tx`/`last_rx` | traffic counters (added by migration) |
| `block_internet` | per-peer WAN block (added by migration, not in base `CREATE`) |

This table is the FK parent for `vpn_acl_rules`, `vpn_virtual_ips`,
`vpn_virtual_ip_acl`, and `domain_routes`.

### `vpn_acl_rules`
Directed "source may reach target" rules between two peers.

| Column | Meaning |
|---|---|
| `source_client_id`, `target_client_id` | FKs → `vpn_clients(id)` **CASCADE** |
| `bidirectional` | if set, the pair can reach each other both ways (added by migration) |

**Invariant:** only one row per client pair — `UNIQUE(source_client_id,
target_client_id)`, and application code checks both directions before insert
(`database.go:298-308`).

### `vpn_virtual_ips`
Extra VPN `/32`s routed to a peer and DNAT'd on that peer to a device on its LAN
(e.g. expose a LAN camera over WG).

| Column | Meaning |
|---|---|
| `client_id` | owning peer, FK → `vpn_clients(id)` **CASCADE** |
| `ip` | the virtual VPN IP, **unique** |
| `label` | display label |
| `target_ip`, `target_port` | LAN device the DNAT points at (added by migration; empty = bare-routed, no forward) |
| `restricted` | `1` (default) ⇒ only peers listed in `vpn_virtual_ip_acl` may reach it |
| `quarantine` | quarantine flag (added by migration) |

**Invariant:** a peer maps a given device IP+port at most once — enforced by a
**partial** unique index `idx_vpn_vip_peer_target ON (client_id, target_ip,
target_port) WHERE target_ip != ''` (bare-routed vips exempt), added by migration
(`database.go:707-730`).

### `vpn_virtual_ip_acl`
Allow-list of which peers may reach a restricted virtual IP (empty ⇒ nobody
until opted in).

| Column | Meaning |
|---|---|
| `virtual_ip_id` | FK → `vpn_virtual_ips(id)` **CASCADE** |
| `source_client_id` | FK → `vpn_clients(id)` **CASCADE** |

`UNIQUE(virtual_ip_id, source_client_id)`.

### `vpn_router_config`
Single-row config (`CHECK(id = 1)`) for the Headscale subnet-router feature.

| Column | Meaning |
|---|---|
| `enabled` | feature toggle |
| `authkey_enc` | **encrypted**, write-only Headscale pre-auth key (single-use, 1-hour-lived, never read back — see the migration note below) |
| `headscale_user` | Headscale user the router registers as (default `vpn-router`) |
| `route_id`, `status`, `last_check` | operational state |

---

## Logs & analytics schema
`database.go:380-472`

### `logs`
Unified log stream for outbound/inbound/DNS/firewall/proxy events. Columns are
prefixed `logs_*` to stay unambiguous in joins.

| Column | Meaning |
|---|---|
| `logs_type` | `outbound` \| `inbound` \| `dns` \| `fw` \| `proxy` (CHECK; `proxy` added by migration) |
| `logs_src_ip`, `logs_src_country` | source |
| `logs_dest_ip`, `logs_dest_port`, `logs_dest_country` | destination |
| `logs_domain`, `logs_protocol`, `logs_status`, `logs_duration`, `logs_bytes`, `logs_cached` | common fields |
| `logs_method`, `logs_path`, `logs_router`, `logs_service` | inbound (HTTP/Traefik) extras |
| `logs_query_type`, `logs_upstream`, `logs_rule` | DNS extras |

Capped by the logs cleanup / retention job (rows are not kept forever).

### `log_rollups`
Hourly per-type aggregate counters, so charts and KPI counters keep real history
after the raw `logs` rows are pruned. Aggregate-only (no IPs/domains).

| Column | Meaning |
|---|---|
| `bucket_hour` | unix seconds floored to the hour |
| `logs_type` | log type |
| `cnt`, `bytes` | totals |
| `blocked` | rows whose status matches `%BLOCK%`/`%FILTER%` |
| `cached` | DNS cache hits |
| `ok` | 2xx (inbound) |

PK `(bucket_hour, logs_type)`. Filled automatically by the **`log_rollup_ai`
AFTER INSERT trigger** on `logs` — every log source is covered with zero
per-watcher code. **Gotcha:** the trigger's `blocked`/`cached`/`ok` expressions
must stay in sync with how `handleGetStats` computes the same numbers from raw
logs, or the rollup and live figures will disagree (`database.go:434-453`).

### `traffic_usage`
Per-peer, per-destination byte rollup, populated by the conntrack watcher —
answers "peer X sent/received N bytes to destination Y" over time buckets.

| Column | Meaning |
|---|---|
| `peer_ip`, `dest_ip`, `dest_port`, `protocol` | flow key |
| `domain`, `dest_country` | enrichment |
| `bytes_up`, `bytes_down` | totals |
| `bucket` | time bucket |

PK `(peer_ip, dest_ip, dest_port, bucket)`.

---

## User PWA schema
`database.go:480-524`

### `users_push_subscriptions`
Web Push (PWA notification) subscriptions.

| Column | Meaning |
|---|---|
| `user_id` | FK → `users(id)` **CASCADE** |
| `device_name`, `user_agent` | device identity |
| `endpoint` | push endpoint URL, **unique** |
| `key_p256dh` | **encrypted** ECDH public key |
| `key_auth` | **encrypted** auth secret |
| `last_used_at` | last delivery |

### `users_notification_preferences`
Per-user notification toggles, key-value for extensibility. `UNIQUE(user_id,
pref_key)`, FK → `users(id)` **CASCADE**.

### `users_device_locations`
GPS device-location history: `latitude`/`longitude` (required), plus optional
`accuracy`, `altitude`, `heading`, `speed`, `recorded_at`. FK → `users(id)`
**CASCADE**.

---

## Fleet schema
Created by the fleet package, not `database.go` — `ensureSchema` in
`api/internal/fleet/service.go:319-407`.

### `fleet_ca`
The fleet's certificate authority (single logical CA).

| Column | Meaning |
|---|---|
| `cert_pem` | CA cert (PEM, public) |
| `key_enc` | **encrypted** CA private key |
| `created_at` | creation time |

### `fleet_tokens`
One-time enrollment tokens for machines joining the fleet.

| Column | Meaning |
|---|---|
| `token_hash` | PK — hash of the token (the token itself is never stored) |
| `label`, `panel_host` | metadata (`panel_host` added by migration) |
| `expires_at`, `used`, `used_at` | lifecycle |

### `fleet_machines`
Enrolled machines.

| Column | Meaning |
|---|---|
| `id` | machine id (PK) |
| `name`, `machine_hash`, `cert_fp`, `wg_pubkey` | identity |
| `status` | default `enrolled` |
| `last_report`, `last_seen`, `enrolled_at` | lifecycle |
| `revoked` | de-enrolled flag |

### `fleet_commands`
Command queue delivered to agents on their next check-in.

| Column | Meaning |
|---|---|
| `id` | PK |
| `machine_id` | target machine |
| `type`, `payload` | what to run |
| `status` | default `pending` |
| `result`, `delivered_at`, `done_at` | outcome/lifecycle |

Indexed `(machine_id, status)`.

### `fleet_cves`
Per-machine CVE findings from the agent's vulnerability scans (Trivy-style).

| Column | Meaning |
|---|---|
| `machine_id`, `cve_id` | which machine, which CVE |
| `pkg`, `installed`, `fixed`, `severity` | package + fix info |
| `target`, `project`, `class`, `type`, `title` | scan context (`project` added by migration) |
| `scanned_at` | scan time |

Indexed `(machine_id, severity)` and `(machine_id, project)`.

### `fleet_metrics`
Per-machine resource metrics, bucketed.

| Column | Meaning |
|---|---|
| `machine_id`, `bucket` | key (PK) |
| `cpu_avg`/`cpu_max`, `mem_avg`/`mem_max`, `disk_avg`/`disk_max`, `load_avg`/`load_max` | per-bucket stats |
| `samples` | number of samples folded into the bucket |

---

## Dynamically-created tables

These are created lazily by their owning package on first use (each with a
`sync.Once` guard where noted), not in `createSchema`:

| Table | Created in | Purpose |
|---|---|---|
| `l7_block_samples` | `firewall/l7stats.go:16-24` | periodic counts of sentinel (Traefik L7) silent-drops, for the "blocked by layer" view; retention-swept |
| `fw_drop_samples` | `firewall/l3stats.go:22-30` | sampled **deltas** of nftables block-set drop packet counters — needed because the firewall table is rebuilt on every apply, resetting kernel counters |
| `sudo_failures` | `server/server_watch.go:27-40` | persisted failed-sudo attempts with the resolved session IP (the "intruder escalating" signal); `UNIQUE(ts, tty)`, `dismissed` column added by inline migration |

---

## Migrations

`runMigrations` (`database.go:538-794`) runs at the end of `createSchema`, every
boot, and is idempotent. There is **no version table** — each migration
self-checks and is safe to re-run. Two patterns are used:

1. **Add-column migrations** — check `pragma_table_info(<table>)` for the column;
   if absent, `ALTER TABLE … ADD COLUMN`. Used for:
   - `vpn_acl_rules.bidirectional`
   - `vpn_clients.total_tx/total_rx/last_tx/last_rx`, `vpn_clients.block_internet`
   - `domain_routes.sentinel_config`, `cert_resolver`, `skip_cert_verify`
   - `jails.escalate_asn`, `escalate_asn_threshold`, `escalate_asn_window`
   - `vpn_virtual_ips.target_ip`, `target_port`, `quarantine`
   - **`vpn_router_config.authkey` → `authkey_enc`** (`database.go:568-578`):
     the notable "encrypt at rest" migration. It adds `authkey_enc` and
     **wipes the legacy plaintext** `authkey` (`UPDATE … SET authkey = NULL`)
     rather than re-encrypting it — the pre-auth key is single-use and
     1-hour-lived, so any stored value is already dead. New writes store the
     encrypted form (`vpn.SetupRouter`).

2. **Table-rebuild migrations** (for changing a `CHECK` constraint — SQLite
   can't `ALTER` one). Guarded by reading `sqlite_master.sql` and checking
   whether the new value is already allowed; done inside a **transaction** so
   the security-critical table is never left partial, with columns enumerated
   explicitly on copy so a future column add can't silently misalign:
   - `firewall_entries` rebuilt to allow the **`asn`** `entry_type`
     (`database.go:621-684`) — failures logged at ERROR and retried next boot.
   - `logs` rebuilt to allow the **`proxy`** `logs_type` (`database.go:732-793`).

3. **One-time data sweeps** (`database.go:686-730`): dedupe duplicate forwarding
   virtual IPs (keep lowest id per `client_id,target_ip,target_port`), then clear
   orphaned `vpn_virtual_ips` / `vpn_virtual_ip_acl` rows left behind by peers
   deleted while FK enforcement was off, then create the partial unique index.
   Row-affecting sweeps log their counts so the change is auditable.

**Fleet migrations** live separately in `fleet/service.go:391-406` (add
`fleet_tokens.panel_host`, `fleet_cves.project`; ignore "duplicate column"),
with dependent indexes created *after* the column adds.

---

## Relationship summary

```
users ─1─┬─< sessions                    (CASCADE)
         ├─< users_push_subscriptions     (CASCADE)
         ├─< users_notification_preferences (CASCADE)
         └─< users_device_locations       (CASCADE)

vpn_clients ─1─┬─< vpn_acl_rules (source & target)   (CASCADE)
               ├─< vpn_virtual_ips                    (CASCADE)
               │        └─< vpn_virtual_ip_acl        (CASCADE)
               ├─< vpn_virtual_ip_acl (source)        (CASCADE)
               └─< domain_routes (vpn_client_id)      (SET NULL)

fleet_machines ──< fleet_commands / fleet_cves / fleet_metrics  (by machine_id, no FK)
```

Fleet child tables reference `machine_id` by convention only — there are **no
declared foreign keys** in the fleet schema, so their cleanup is application-
managed rather than FK-cascaded.

---

## Unverified / flagged

- The relationship diagram's fleet edges are **logical** (`machine_id` join
  keys), not enforced FKs — confirmed by the absence of `FOREIGN KEY` clauses in
  `fleet/service.go:319-385`.
- The "notable non-encrypted settings keys" list is gathered from grep across
  `api/internal` and is representative, **not exhaustive** — settings is an
  open key-value store, so other keys may be written at runtime.
- Test-only schemas (`rekey_test.go`, `backup_test.go`, `cf_only_test.go`) were
  read to cross-check the encrypted-column set but are not part of the runtime
  database.
