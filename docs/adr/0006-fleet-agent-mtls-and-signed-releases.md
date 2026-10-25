# 0006 — Fleet agent: mTLS enrollment + signed releases

- **Status:** Accepted (recorded retroactively, 2026-10-17)

## Context

The fleet feature runs a per-machine agent that reports inventory/CVEs and accepts commands from
the panel. Two trust problems: the panel must know a connecting agent is genuinely enrolled (not
an impostor), and an agent must know an auto-update binary genuinely came from its panel (not a
MITM or a tampered mirror).

## Decision

- **Enrollment & transport:** each agent gets a client certificate at enrollment and connects
  over **mTLS**; the panel authenticates the agent by its cert. On **uninstall the cert is
  revoked** (fixed 2026-10-17) so access dies immediately, not at expiry.
- **Releases:** agent binaries are **signed** (`tools/motte-sign`, key `signing.key` which is never
  committed) and the agent verifies the signature before applying an update. Release packaging is
  `make release` (config in `agent/release.env`).

## Consequences

- (+) Both directions of the fleet channel are authenticated; a revoked agent is locked out at
  once.
- (+) A tampered or substituted agent binary fails signature verification.
- (−) The signing key is a critical secret kept out of the repo and off the panel; its loss means
  cutting a new key and re-trusting agents.
- (−) Cert lifecycle (issue/revoke/rotate) is now something the panel must manage correctly.

## Update (2026-10-18) — signed-update hardening

The self-update path (`agent/selfupdate.go`) gained three defences, so a validly signed but
malicious or stale release can no longer harm an agent:

- **Anti-rollback.** After the staged binary passes signature + checksum verification, the agent
  reads the binary's own (now-authenticated) version and refuses to activate anything older than
  the highest version this host has ever run. That floor is persisted beside the binary
  (`.motte-agent.floor`), so a downgrade is refused even across a restart or reinstall — a compromised
  panel cannot push a known-vulnerable old release.
- **Selftest-before-swap.** A dependency-free `motte-agent selftest` subcommand (ed25519 roundtrip +
  self-locate) is run on the staged binary before the atomic swap, catching a wrong-arch or
  broken-but-hash-matched build before it replaces the live one.
- **Key rollover.** The baked-in `signPubKey` now accepts a *list* of public keys; a release
  verifies if **any** key accepts it. A rotation bakes {retiring, new} together, re-signs with the
  new key, and retires the old one in a later build — with no window where agents stop updating. A
  present-but-unparseable key set still fails closed. Mirrored in panel + agent; the build
  (`agent/Makefile`, `manage.sh`) comma-joins a multi-line `signing.pub`.
