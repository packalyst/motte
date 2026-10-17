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
- **Releases:** agent binaries are **signed** (`tools/wgsign`, key `signing.key` which is never
  committed) and the agent verifies the signature before applying an update. Release packaging is
  `make release` (config in `agent/release.env`).

## Consequences

- (+) Both directions of the fleet channel are authenticated; a revoked agent is locked out at
  once.
- (+) A tampered or substituted agent binary fails signature verification.
- (−) The signing key is a critical secret kept out of the repo and off the panel; its loss means
  cutting a new key and re-trusting agents.
- (−) Cert lifecycle (issue/revoke/rotate) is now something the panel must manage correctly.
