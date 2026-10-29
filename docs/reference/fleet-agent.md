# Fleet Agent (`motte-agent`)

The per-machine fleet agent lets the panel monitor and lightly manage other Linux
hosts. It lives in `agent/` (Go, **git-ignored** — see `.gitignore:53-54` and
`agent/.gitignore`) and talks to the panel-side subsystem in
`api/internal/fleet/`. Binaries are never committed; they ship as GitHub releases.

Agent module: `agent/` (package `main`, binary `motte-agent`). Agent version constant:
`agent/report.go:26` (`agentVersion = "0.1.22"` at time of writing).

Related: [security.md](security.md) · [networking-firewall.md](networking-firewall.md) · [data-model.md](data-model.md) · [deployment.md](deployment.md) · [api-surface.md](api-surface.md)

See also memory: [fleet-agent-build], [fleet-installer-domain-path], [fleet-cve-feature], [agent-release-process].

---

## 1. What the agent does

Per-machine telemetry + light enforcement, all confined to its own directory tree
so uninstall leaves the host pristine (`base_dir` / `data_dir` / `conf_dir`):

- **Metrics** — CPU / memory / disk / load / uptime read directly from `/proc` (`agent/metrics.go`, `agent/report.go`).
- **CVE scanning (Trivy)** — scans OS packages **and** app dependencies (npm/composer/pip/go lockfiles auto-discovered by `trivy fs`). Slow/expensive → **on demand only**: never on install, boot or a timer. Trivy is installed by the first scan, each scan refreshes its own DB when stale, and the last result is saved (`/var/lib/motte-agent/trivy/last-scan.json`, 0600) so it survives restarts. The `rescan` command runs it in the background; the report carries `scanning` / `scan_error`. `agent/tool_trivy.go`, `Manager.Scan`.
- **Intrusion detection (CrowdSec)** — the agent reads CrowdSec's local decisions (`--limit 0`: all of them) and enforces them itself via its own nftables table (replaces the bouncer). Rules: the SSH set only, no GeoIP enrichment (converged at install and every hub update); the daemon runs with `GOMEMLIMIT=64MiB GOGC=25`. Its local API listens on 127.0.0.1 only and no Central API / Console is configured. `agent/tool_crowdsec.go`.
- **Host facts** — OS, kernel, CPU, RAM, listening ports, read natively from `/proc`, `/sys`, `/etc` (no subprocess); hardware/OS/kernel once at start, the rest every minute. `agent/hostfacts.go`.
- **FIM (osquery)** — File Integrity Monitoring via a supervised `osqueryd`: system and `/usr/local` programs, the agent's binaries, `/etc`, SSH keys, scheduled tasks (`/var/spool/cron`), system services (`/usr/lib/systemd/system`), and the agent's config folder with the tools' settings in it (only CrowdSec's rule downloads are left out). Each report carries up to 1000 changed files, the latest change per file, shared out between folders so a flood in one can't push a change elsewhere out of view; a final `DROPPED` entry counts what didn't fit. The agent's own writes are dropped: its config files by content and time, a tool's folder while the agent installs, starts, updates or removes that tool. Everything else there is reported. `agent/tool_osquery.go`, `agent/ownwrites.go`.
- **Enforcement** — blocks source IPs via its own nftables table (`inet motte_agent`: sets `blocked_ips` / `blocked_ips6` for manual blocks and CrowdSec bans, `panel_blocklist` for the panel-pushed list). The agent's saved state (`<data_dir>/blocks.json`, root-only) is the truth, with each entry's sources (manual, crowdsec, panel); the kernel table is rebuilt from it in one atomic `nft -f` transaction at start (a reboot empties the kernel's rules), on every change, when dry-run changes, and by a once-a-minute self-heal (a failed save or apply, or a table that went missing). Dry-run enforces nothing: the table is removed and the list kept. An address stays blocked while any source still wants it; unblocking also drops CrowdSec's ban. The same drops sit in two chains: `input` (traffic for the host) and `forward` (traffic through it, above all to Docker-published ports, which are rewritten to the container before they'd reach `input`). Only replies to connections the host or a container opened are accepted ahead of the drops, so a ban also ends a blocked address's existing sessions. Addresses that would hurt the host (loopback, its own, multicast, link-local) are refused, and the panel list also refuses private and reserved addresses (single or range: RFC 1918, 100.64/10 CGNAT/Tailscale), so a push can't cut off the operator's own VPN or LAN. If nft rejects the rules while a panel list is present (a timeout, a limit), the manual and CrowdSec bans are applied without it and the failure is reported, so one bad list never leaves the host with no rules. `agent/enforce.go`.
- **Kernel maintenance** — install newest kernel, reboot to activate, purge superseded kernels + rescan, as a reboot-surviving state machine. `agent/kernelmaint.go` (`KernelMaint`).

The **sub-agents (tools)** are installed only from a pinned `manifest.json`
(URL + sha256 per tool/arch, fail-closed on empty hash). Downloads are
checksum-verified byte-for-byte. Everything runs as an argv — never `sh -c` of
untrusted input (`agent/tool.go`, `agent/manifest.go`).

The single report snapshot the agent publishes is `Report` (`agent/report.go`):
`agent`, `host`, `time`, `dry_run`, `log_level`, `metrics`, `blocks` (with sources), `block_error`, and the
optional sub-agent sections `intrusion` / `cves` / `facts` / `kernel` (absent
until their tool has gathered).

---

## 2. Run mode

The agent runs only bound to a panel: `agent/main.go` refuses to start without `panel_url`, or with
one that isn't `https://` (enrollment, commands and the console never travel unencrypted). It
**must enroll first**, then runs the mTLS report/command loop; the panel is the only way in, and
there is no local control port. If enrollment fails (panel down / bad token), it retries every 30s
and starts **no** sub-agents until it succeeds. (An early dev-only local HTTP API, unauthenticated
on loopback, was removed: any local user could have used it to run apt or reboot the host.)

---

## 3. Config (`agent/config.go`)

Plaintext JSON at `/etc/motte-agent/config.json` (default). **No secrets in the JSON,
no secrets from env** — operational config only. Secrets live in the encrypted
store (§7). Written on demand with `motte-agent -config … -write-default-config`.

Key fields (`Config` struct):

- Transport: `panel_url`, `ca_fingerprint` (pinned `sha256:<hex>`, from the install command), `enroll_token` (one-time; consumed + scrubbed on first enroll).
- Loops: `metrics_interval` (default 15s — also the report cadence), `db_update_every` (12h, CrowdSec hub). CrowdSec decisions + host facts refresh every minute (fixed). No scan loop.
- Firewall: **`dry_run` (default `true`)**, `nft_table` (`motte_agent`), `nft_set` (`blocked_ips`).
- `log_level`: `quiet` (default) or `debug`, flipped live by the `set-log-level` command.
- Layout: `base_dir` (`/opt/motte-agent`), `data_dir` (`/var/lib/motte-agent`), `conf_dir` (`/etc/motte-agent`), `manifest_path`.
- `tools`: `{trivy, crowdsec, osquery}` booleans (all `true` by default).
- `scan_roots`: Trivy scan roots (empty ⇒ whole `/`).

`dry_run` and `log_level` are mutated live from the panel-poll goroutine while
collector/blocker goroutines read them, so they're guarded by an `RWMutex` —
always go through `IsDryRun()`/`SetDryRun()` and `Debug()`/`SetLogLevel()`
(`config.go:57-96`). `Save()` writes the file `0600`.

**Dry-run default gotcha:** with `dry_run: true`, firewall/update/reboot actions
are **logged, not applied**. This also suppresses the deregister ping on uninstall
(§6). The installer's `--live` flag flips it off; the panel can flip it live with
`set-dry-run`.

---

## 4. Enrollment (mTLS, one-time token)

The trust model: the panel runs a **private CA**; agents generate their own
keypair locally (private key never leaves the host), send only a CSR, and the
panel signs a short-lived client cert. The panel then only obeys agents whose
cert its own CA signed and that map to a live, non-revoked machine.

### Panel side (`api/internal/fleet/`)

- **CA (`ca.go`)** — `loadOrCreateCA` generates a P-256 CA on first use, stores the cert in the clear and the **private key AES-256-GCM-encrypted** with the panel's `ENCRYPTION_SECRET` (`fleet_ca` table). `Fingerprint()` = `sha256:<hex>` of the CA cert (what agents pin). `SignClientCSR` verifies the CSR signature and issues a client cert (`ExtKeyUsageClientAuth`, TTL `clientCertTTL = 90 days`, `service.go:88`). **Renewal (`renew.go`, agent `renew.go`)**: within 28 days of expiry the agent (checked hourly) generates a new key locally and `POST /renew`s a CSR over its current mTLS identity; the panel only accepts it within 30 days of the presented cert's expiry, signs it for the same machine, and stores it as `cert_fp_next`. Both certs work until the agent first connects with the new one, which promotes it (`syncCert`) and retires the old — so an interrupted renewal can't lock a machine out. The agent accepts the answer only if it chains to its pinned CA, names this machine and carries the new key. `cert_expires` is shown on the machine page. `ServerCertificate` mints the listener's in-memory server cert, SANs = all non-loopback host IPs + the SSL domain, chain includes the CA so a pinning agent can verify it; `serverCertificate` (`servercert.go`, the listener's `GetCertificate`) keeps it current: 90 days, replaced with 30 left or when the host's IPs/domain change.
- **Listener (`listener.go`, `service.go`)** — a **managed mTLS HTTPS listener** whose on/off + port come from **Settings** (`fleet_enabled` / `fleet_port`, default port **9443**), not env. Enabling it also **opens its port through the firewall** (via the allowed-ports table) and closing disables + closes it (`applyConfig`/`stopLocked`). TLS `ClientAuth: VerifyClientCertIfGiven` — `/enroll` needs no client cert (token-gated) but any cert presented must be CA-signed, so report/command endpoints reject certless/foreign connections **at the handshake**.
  - **Changing the port** with agents enrolled keeps the old port open beside the new one and sends `set-panel-port` to every machine. The old port closes once each of them has **connected on the new port** (seen from the local port of its requests), not when it merely received the command. Machines still missing after 5 minutes (offline, or unable to reach the new port) keep it open up to 24 hours and are named in the audit log; one that keeps turning up on the old port is sent the new one again every 10 minutes. Meanwhile the port can't change again, but the listener can still be switched off and the old port can be closed early ("Close old port now", admin with a step-up: the machines not yet moved are cut off and need reinstalling). On the agent, a moved address that doesn't connect within 2 minutes alternates with the previous one until one of them works; neither is dropped before that.
- **mTLS gate (`mtls.go`)** — `requireClientCert` wraps report/command handlers: requires a peer cert AND that its fingerprint maps to a non-revoked machine (`machineByCertFP`). A valid-but-unregistered or revoked cert → 401. The authenticated `*Machine` is attached to the request context — handlers take the machine from the cert, never the body, so an agent can only act on itself.
- **Tokens (`tokens.go`)** — `CreateToken` mints a one-time token: 32 random bytes, stored **only as a SHA-256 hash** with a label, `panel_host` (the direct origin IP the agent will dial for mTLS), and expiry (default 1h). `redeemToken` is an **atomic single-`UPDATE`** guarded by `used=0 AND not expired`, so a token can never be used twice. `lookupToken` peeks (does not consume). Pending tokens are listable (metadata only, never the secret) and cancellable by rowid.
- **Enroll handler (`enroll.go`)** — `POST /enroll`: validate CSR shape → `redeemToken` → assign a random `machine_id` (= cert CN) → `SignClientCSR` → sanitize the self-reported hostname (`sanitizeMachineName`: ASCII + `. _ - space`, ≤64 chars, drops XSS bytes before they reach the DB) → `registerMachine` → return `{machine_id, client_cert, ca_cert}`. Errors on the token are deliberately vague (no invalid-vs-used-vs-expired distinction).

### Agent side (`agent/register.go`)

`Enroll` (called from `main.go` before any sub-agent starts, retrying on failure):
1. Refuse if `panel_url`, `enroll_token`, or `ca_fingerprint` are missing — a missing fingerprint would be trust-on-first-use, explicitly rejected (`register.go:54-56`).
2. Generate a P-256 keypair locally, build a CSR (CN = hostname).
3. `POST /enroll` with `{token, csr, machine_id (/etc/machine-id), hostname, wg_pubkey}` over TLS whose server cert is **pinned** to `ca_fingerprint` (`pinnedTLS`: `InsecureSkipVerify` + a custom `VerifyPeerCertificate` that requires the pinned CA in the chain and verifies the leaf against it — closes the first-contact gap).
4. Store `{private_key, client_cert, ca_cert, machine_id}` in the encrypted store (§7).
5. **Scrub the one-time token** from `config.json` (it's now consumed) so it can't linger in a possibly world-readable file (`register.go:98-105`).

`Enrolled(store)` = the store holds a `ClientCertPEM`. The daemon skips re-enroll
if already enrolled.

The stored **machine identity hash** (`sha256(machine-id | wg_pubkey)`,
`store.go:machineIdentityHash`) is a provenance anchor captured at enroll. **Note:**
it is **not** yet consulted on report — the enforced runtime binding is the client
cert fingerprint, not this hash (documented in the code as a future replay check).

---

## 5. Reporting & commands (mTLS loop)

### Agent → panel (`agent/panel.go`, `PanelClient`)

Built from the stored identity (client cert + key + pinned CA pool, `MinVersion
TLS 1.2`). `Run` drives two tickers:
- **report** every `metrics_interval` (default 15s): `POST /report` with `col.Latest()` (the snapshot). Panel stores it as `last_report`, bumps `last_seen`, sets `status='online'`, folds metrics into 5-min history buckets, and broadcasts it to any watching browser over WS (`api/.../report.go`, `metrics.go`).
- **link** (`GET /link`, persistent mTLS WebSocket, `agent/link.go` ↔ `api/internal/fleet/link.go`): a doorbell + presence channel. When a command is queued the panel sends `{"t":"commands"}` and the agent fetches at once over the normal `GET /commands` (no command data rides the link). Panel pings every 10s; 25s of silence = dead. The link **is** the machine's online state (`online` on `/api/fleet/machines` and the clients list, pushed on the `fleet` WS; a drop counts as offline after a 20s grace, and at once when the agent says it's going away, e.g. a reboot) — never guessed from report age. Commands are only queued for an online machine. Revoke/delete closes it at once.
- **command fetch**: `GET /commands` → run each → `POST /commands/ack`, on every ring, on every (re)connect, and once a minute as a safety net while the link is up. Nothing polls while it's down (the panel queues nothing for an offline machine). A 10s tick advances a pending kernel-reboot state machine.
- **report** sections `cves`/`intrusion`/`facts` are sent only when they changed (or every 10 min); otherwise the report is marked `partial` and the panel keeps its stored copy.
- **CVE report**: once per new scan (keyed by `scanned_at`), the **full** Trivy findings ship gzip-compressed to `POST /cve-report` (the 15s report only carries a summary). `maybeSendCVEs`/`sendCVEReport`.

**401/403 handling:** if the panel rejects the identity (machine deleted/revoked),
the agent counts consecutive rejections and, after 3, **stops panel sync** — but
deliberately does **not** tear down local protection (CrowdSec/osquery keep
running), so a panel-side delete can't become a remote kill-switch. Re-enrolling
with a fresh token brings it back (`panel.go:81-95`).

### The command allowlist (defense in depth)

The panel's `allowedCommands` map (`api/internal/fleet/commands.go:17-29`)
and the agent's `exec` switch (`agent/panel.go:223-334`) **both** enforce the same
fixed set — never a shell string. A compromised panel row still can't make the
agent run arbitrary code:

`block`, `unblock`, `apply-updates`, `fix-packages` (targeted OS-package upgrades
for selected CVEs), `update-kernel`, `restart` (`tools`|`host`), `set-dry-run`,
`set-log-level` (`quiet`|`debug`), `update-agent` (self-update), `rescan` (Trivy
now), `sync-blocks` (push the panel's blocklist onto the host). Anything else →
`command not allowed`.

A `rescan` can carry folders for scans to skip. Adding one hides its findings, so it takes an
admin and a step-up; keeping or shrinking the list stays an operator action. The check runs
whether or not the machine is online (it could come online in between), so adding folders on an
offline machine can ask for the step-up before the request is refused as offline.

### Local policy (a lock the panel can't change)

Root on a server can create `/etc/motte-agent/local-policy.json` to switch capabilities off
whatever the panel asks — useful on sensitive hosts, since whoever controls the panel
otherwise controls the console, agent updates and host maintenance:

```json
{"no_console": true, "no_self_update": true, "no_host_maintenance": true}
```

It is checked on every console action (re-read whenever the file changes), so an edit applies
at once: `no_console` refuses `set-console`, keeps the console channel from starting or
reconnecting, ends a running one at its next action, and refuses folder listing (the
scan-exclude picker) too; `no_self_update` refuses `update-agent` (root updates the binary by
hand); `no_host_maintenance` refuses `apply-updates`, `fix-packages`, `update-kernel` and
`restart host` (restarting the agent's own tools still works). A running console also re-checks
the file every 5 seconds, so a lock applies while a session sits idle. The security commands
(blocks, dry-run, tools) are never locked.

**Only `no_console` is a real boundary on its own.** With the console allowed, the panel can
open a root shell, and a root shell can do anything the other switches forbid — install
packages, reboot, replace the agent binary, edit or delete this very file. So `no_self_update`
and `no_host_maintenance` mean something only together with `no_console`; set it whenever you
set them. A console locked while running is torn down like turning it
off (its shells end), and starts again on the next `set-console` once the lock is lifted. No file
locks nothing; a file that can't be read or parsed, names a key it doesn't know (a misspelt
switch), holds anything but one JSON object (`null`, text after it), locks everything, so a typo
never quietly undoes a lock. So does a file, or any folder above it, that someone other than root
could change (they could delete it, and no file means no lock). `agent/policy.go`.

### Panel command lifecycle (`api/.../commands.go`)

`Enqueue` (allowlist-checked) inserts a `pending` row (`fleet_commands`).
`HandleCommands` returns a machine's pending commands and marks **only the rows it
actually returned** delivered (a command enqueued in the SELECT→UPDATE window
stays pending for the next poll). `HandleCommandAck` records `done`/`error` +
result, bound to `machine_id` so an agent can only ack its own. Each transition
(enqueue/deliver/ack) broadcasts the command log over WS so the detail page
updates live without polling.

Admin-side operator API (on the **normal authenticated** router, registered as the
`fleet` service — `admin.go`): `CreateToken`, `ListTokens`, `DeleteToken`,
`ListMachines`, `CAInfo`, `EnqueueCommand`, `MachineReport`, `MachineCommands`,
`MetricsHistory`, `FleetEndpoints`, `SetConfig`, `PushBlocks`, `DeleteMachine`,
plus CVE handlers (`CVEGroups`, `ListCVEs`, `ListCVEsByCVE`, `ExportCVEs`,
`FixPackages`).

---

## 6. Uninstall / deregister

`motte-agent uninstall` → `RunUninstall` (`agent/uninstall.go`). Order matters:
1. **Deregister from the panel first** (`deregisterFromPanel`), while still enrolled, over the agent's mTLS identity → `POST /deregister`. **Best-effort — never blocks uninstall.**
2. `systemctl disable --now motte-agent` (stop the daemon + supervised children, wait 1.5s so file removal doesn't race them).
3. Remove sub-agents + their data (`mgr.UninstallAll()`).
4. Drop the `inet motte_agent` nftables table.
5. Wipe secrets + key material.
6. `rm -rf base_dir / data_dir / conf_dir`.
7. Remove the systemd unit; unlink the binary itself (`removeSelf`, guarded to the real `motte-agent` name so it never deletes a test binary).

### The deregister → MarkUninstalled flow

Panel `HandleDeregister` (mTLS) calls `MarkUninstalled(id)`: the cert is **revoked**
(`revoked=1`), the console is switched off and an activity entry (`machine_uninstalled`) is
written. The machine's **history is kept** — queued commands, CVEs, FIM events, scans, usage
history (`machineDataTables`) and its console recordings — because the request comes from the
machine itself: an intruder on it must not be able to erase the evidence. The stored report and
tags are cleared; the UI shows a dedicated "Agent uninstalled" page with **Remove from panel**.
`DeleteMachine` (an admin, with step-up) deletes all of that data and the recordings + their keys
(`purgeRecordings`, matched by the recording header, not the filename) and removes the row too,
which invalidates the client cert (mTLS auth requires a live cert_fp lookup), so the host must
re-enroll with a fresh token to return. Both close the live link and console at once.

**Dry-run gotcha:** `deregisterFromPanel` early-returns under `dry_run`
(`uninstall.go:79-82`) — it logs `[dry-run] deregister from panel` and sends
**nothing**. So a dry-run uninstall never notifies the panel; the machine stays
whatever status it had (typically drifts to offline) rather than "uninstalled".
And `RunUninstall` returns a "nothing was actually removed" error under dry-run.
Real removal requires `dry_run: false`.

---

## 7. Secrets store (`agent/secrets.go`)

`Secrets` = `{enroll_token, private_key_pem, client_cert_pem, panel_ca_pem,
machine_id}`, **never** written plaintext, **never** read from env. Stored as
`secrets.enc` (AES-256-GCM, `0600`) under `conf_dir`. The AES-256 key is derived
via **HKDF-SHA256** from two inputs:
- `<conf_dir>/agent.key` — 32 random bytes, `0600` root-only, created on first run;
- `/etc/machine-id` — binds the ciphertext to this host.

What it protects (per the code comment): a local unprivileged user can't read the
secrets (perms), and moving `secrets.enc` alone — or `secrets.enc`+`agent.key` — to
another host fails (missing key / different machine-id). It does **not** protect
against a full-host exfiltration (backup/snapshot/`tar /etc /var`) that captures
all three inputs together — the security there is the file permissions; the
machine-binding is a second factor against loose-file copies, not backups.

---

## 8. Install / systemd

`agent/install.sh` (POSIX sh) is the real installer (`./install.sh
check|install|uninstall`). Flags: `--binary`, `--manifest`, `--no-start`,
`--no-systemd`, `--live` (enforce for real; default is dry-run/safe),
`--remove-fail2ban`, `--panel URL`, `--ca-fp FP`, `--token TOKEN`. Path overrides
via env: `PREFIX`, `CONFDIR`, `BASEDIR`, `DATADIR`. It re-execs as root (before arg
parsing, so `"$@"` survives the sudo hand-off) and, when no local binary is given,
downloads from the repo's **latest** GitHub release (`AGENT_RELEASE=agent-vX.Y.Z`
pins a specific one).

`agent/systemd/motte-agent.service`: `Type=simple`,
`ExecStart=/usr/local/bin/motte-agent -config /etc/motte-agent/config.json`,
`Restart=always`, **`User=root`** with `AmbientCapabilities=CAP_NET_ADMIN
CAP_NET_RAW` (it manages nftables, supervises tools, reads host logs). Hardening is
kept permissive on purpose (`ProtectHome=false`, `ProtectSystem=false`).

### Panel-served self-extracting installer (the one-command path)

The panel serves a **self-extracting** installer so a new box needs nothing
pre-staged (`api/internal/fleet/install.go`, `HandleInstallScript`):

- `GET /agent/{token}?arch=<uname -m>` — served on the **main api router** (public, no session — the one-time token in the path is the credential) and published over **Traefik/443 on the panel domain** (`fleetroute.go` generates `traefik/dynamic/fleet.yml`; the route exists only when the listener is ON and a domain is configured, and carries `sentinel_fw_block` only when the "Enforce Firewall on Proxied Traffic" setting is on). This is deliberately **not** on the mTLS listener — the download rides the panel's real cert + Traefik's rate-limit/blocklist middleware (one guarded door).
- It returns a `#!/bin/sh` script with the agent **binary** (for the requested arch), the **manifest**, and the **real `install.sh`** all base64-embedded (base64 so the installer's own heredocs can't clash), plus `--panel <IP:port>`, `--ca-fp <fingerprint>`, `--token` spliced in. It decodes to a tempdir and hands off to the bundled installer — so **all** install logic stays in `install.sh` (no duplication).
- `panelHost` is the **direct origin IP** the operator picked when minting the token (recorded with the token), NOT the Cloudflare-proxied download domain (which only forwards 443 and can't pass client certs). The install command generated by `handleCreateToken` (`admin.go:200`) is: `curl -fsSL "https://<domain>/agent/<token>?arch=$(uname -m)" | sudo sh`. Without a domain, no one-command install is offered.
- On a bad token/arch or a cache/fetch failure it returns a **runnable error script** (a friendly bordered message + `exit 1`) so `curl | sudo sh` prints cleanly.

### Agent asset cache (`api/internal/fleet/agentcache.go`)

The panel carries **no** binaries; it pulls the agent's binary + manifest +
`install.sh` **live** from the latest GitHub release and caches them on disk
(`FLEET_AGENT_CACHE`, default `/data/fleet-agent`). Freshness marker without the
GitHub API: the release's tiny `checksums.txt` is re-fetched at most every 5 min;
if it changed, a new release is out → purge cache + lazily re-download. Binaries
are **checksum-verified against `checksums.txt` before ever being served**
(fail-closed). `LatestVersion` (GitHub API, cached 30 min) feeds the UI's "update
available" indicator (`FleetEndpoints`).

---

## 9. Release process (`agent/Makefile`, `agent/gen-manifest.sh`)

Per memory [agent-release-process]: ship with `make release TAG=agent-vX.Y.Z`.

`make release` = `test build manifest checksums` then `gh release create`:
- **build**: cross-compile `motte-agent-linux-amd64` + `motte-agent-linux-arm64`, `CGO_ENABLED=0`, `-trimpath -ldflags "-s -w"` (static, any-libc).
- **manifest** (`gen-manifest.sh`): resolves the **latest** upstream releases of Trivy, osquery, CrowdSec, records a verified sha256 per tool/arch (fail-closed), and writes `manifest.json` with the correct in-archive bin paths. Run at release time only; agents never chase "latest" at runtime — the manifest is pinned + immutable per release.
- **checksums**: `sha256sum` of both binaries → `checksums.txt`.
- publishes `motte-agent-linux-{amd64,arm64}`, `manifest.json`, `checksums.txt`, and `install.sh` as the release assets, `--generate-notes`.

`install.sh` and the panel's cache both track `releases/latest`, so **there's no
version to bump in code** — publishing a new release is the whole ship. To reissue,
delete the old tag and re-run `make release` (per memory).

---

## 10. Panel-side data model (fleet tables)

Created by `ensureSchema` (`api/internal/fleet/service.go:319-407`):

- `fleet_ca` — the CA cert (clear) + encrypted key.
- `fleet_tokens` — one-time enrollment tokens (`token_hash` PK, `label`, `panel_host`, `expires_at`, `used`/`used_at`).
- `fleet_machines` — the registry: `id`, `name`, `machine_hash`, `cert_fp`, `wg_pubkey`, `status`, `last_report`, `enrolled_at`, `last_seen`, `revoked`.
- `fleet_commands` — queued commands with lifecycle (`pending`→`delivered`→`done`/`error`), indexed by `(machine_id, status)`.
- `fleet_cves` — persisted Trivy findings per machine (see below).
- `fleet_metrics` — 5-min usage-history buckets (`cpu/mem/disk/load` avg+max, samples), PK `(machine_id, bucket)`.

`sweepOrphans` runs once at boot to delete child rows whose machine no longer
exists (self-heal for pre-cascade deletes), VACUUMing if the cleanup was large.
Migrations (`ALTER TABLE ADD COLUMN`, ignoring "duplicate column") run before
indexes that reference the migrated columns.

### CVE persistence + drill-down (`api/internal/fleet/cves.go`)

Per memory [fleet-cve-feature]. `IngestCVEs` **replaces** a machine's stored
findings with the latest full scan in one transaction (a snapshot, not history —
the newest scan is the truth), batched up to 1000 rows/INSERT.

Drill-down is **grouped by OS / project** via `deriveProject`:
- OS packages → `"OS"`, except **kernel-family packages** (`linux-image`,
  `linux-headers`, …) → `"Kernel"` (fixed by a new kernel + reboot via
  `update-kernel`, **not** a per-package `apt --only-upgrade`, which can't touch
  them — `isKernelPkg`).
- app dependencies → the **directory** of the manifest (so `go.mod`+`go.sum` group
  together), not the raw file path.

The UI leads with actionable numbers (unique CVEs, affected packages, severity
split, **fixable** = findings with a fix available) rather than the noisy raw
`total` (CVE×package). `CVEGroups`/`ListCVEs`/`ListCVEsByCVE`/`ExportCVEs` (CSV)
serve the drill-down. The **targeted OS-package fix** path: the operator selects
CVEs → `FixPackages` enqueues a `fix-packages` command with the package list → the
agent runs targeted `apt` upgrades (dry-run-aware).

---

## Unverified / flagged

- `agent/kernelmaint.go`, `agent/maintenance.go`, `agent/enforce.go`, `agent/manager.go`, `agent/manifest.go`, and the individual `tool_*.go` files were referenced from `main.go`/`panel.go` but not read line-by-line — their behavior above is summarized from callers, the README, and doc comments. The kernel state-machine phases and the exact `apt`/`fix-packages` argv were not transcribed.
- `agent/install.sh` was read only through line ~90 (detection + arg re-exec); the actual install steps (writing config.json, systemd, tool bootstrap) below that were not transcribed in full.
- The full CVE ingest handler `HandleCVEReport` and `MetricsHistory` handler bodies were not read; described from the schema + `panel.go` sender and the admin handler list.
- `agent/selfupdate.go` (`update-agent`) was seen only via greps: it compares `agentVersion` to the latest release and swaps the binary; details not fully transcribed.
