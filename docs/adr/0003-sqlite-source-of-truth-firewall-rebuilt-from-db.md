# 0003 — SQLite is the source of truth; the firewall is rebuilt from it

- **Status:** Accepted (recorded retroactively, 2026-10-17)

## Context

The panel's state (peers, ACLs, virtual IPs, DHCP networks, settings) has to live somewhere, and
the live kernel state (nftables rules, `ip addr`, WireGuard peers) has to be derivable from it
and survive reboots. Two anti-patterns to avoid: treating the kernel as the source of truth
(unmanageable, un-auditable) and hand-patching individual rules (drift, partial failures).

## Decision

A single **SQLite** database (`api_data` volume) is the source of truth. Kernel state is
**generated** from it: on apply, the relevant nft table is rendered in full, validated with
`nft -c`, then swapped in atomically — never incrementally patched. Schema evolves via
`CREATE TABLE IF NOT EXISTS` + additive `ALTER TABLE … ADD COLUMN` migrations in
`api/internal/database`, so an existing DB upgrades in place on deploy.

## Consequences

- (+) Rebuild-from-DB makes state reproducible and reboot-safe; a bad render fails `nft -c`
  before it can touch the live ruleset.
- (+) Backups are just the sealed DB (see [0005](0005-backups-sealed-with-argon2id.md)).
- (−) The `api_data` volume is precious — the update flow must never `down -v` it; this is the
  documented update gotcha.
- (−) Additive-only migrations mean no destructive schema changes without a deliberate migration
  path.
- Related: [0001](0001-host-networked-privileged-api-with-socket-proxy.md), [0002](0002-nftables-is-the-gate-headscale-acl-advisory.md).
