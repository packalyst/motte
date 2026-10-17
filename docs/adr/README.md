# Architecture Decision Records

An ADR captures **one significant decision**: the context that forced it, the choice made, the
alternatives rejected, and the consequences (good and bad). The `docs/reference/` manual
describes *how the system works today*; ADRs record *why it is that way* and are the place to
look before reversing a load-bearing choice.

These were seeded from decisions already embodied in the code (recorded retroactively), plus the
ones made while building the DHCP feature and the security audit of 2026-10-17.

## Format

Lightweight [Nygard/MADR](https://adr.github.io/) style. Each record has: **Status**, **Context**,
**Decision**, **Consequences**. Status is one of `Proposed` · `Accepted` · `Superseded by NNNN` ·
`Deprecated`.

## Writing a new one

Copy the shape of an existing record, number it next in sequence (`NNNN-kebab-title.md`), and add
a row below. A PR that makes or reverses an architectural decision should add or supersede an ADR
in the same change (see [CONTRIBUTING](../../CONTRIBUTING.md)).

## Index

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-host-networked-privileged-api-with-socket-proxy.md) | Host-networked, privileged `api` with a Docker socket-proxy | Accepted |
| [0002](0002-nftables-is-the-gate-headscale-acl-advisory.md) | nftables is the enforcement gate; the Headscale ACL is advisory | Accepted |
| [0003](0003-sqlite-source-of-truth-firewall-rebuilt-from-db.md) | SQLite is the source of truth; the firewall is rebuilt from it | Accepted |
| [0004](0004-secrets-encrypted-at-rest-with-rekey.md) | Secrets encrypted at rest (AES-256-GCM) with a rekey path | Accepted |
| [0005](0005-backups-sealed-with-argon2id.md) | Backups sealed with Argon2id; plaintext secrets only inside the seal | Accepted |
| [0006](0006-fleet-agent-mtls-and-signed-releases.md) | Fleet agent: mTLS enrollment + signed releases | Accepted |
| [0007](0007-client-ip-trust-model.md) | Real client IP via trusted-proxy + CF-Connecting-IP, fail-closed | Accepted |
| [0008](0008-dhcp-scoped-ip-addr-not-netplan-apply.md) | DHCP: scoped `ip addr` + netplan drop-in, reachability in nft | Accepted |
| [0009](0009-degrade-dont-crash-on-subsystem-init.md) | Degrade (don't crash) on subsystem init failure; surface it | Accepted |
| [0010](0010-two-tier-ci.md) | Two-tier CI: blocking green checks + advisory scanners | Accepted |
| [0011](0011-drop-docker-exec.md) | Remove docker-exec (`EXEC=1`) by moving Headscale ops off the CLI | Proposed |
