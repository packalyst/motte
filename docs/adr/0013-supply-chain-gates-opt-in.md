# 0013 — Supply-chain gates (digest pinning, cosign, health-gated rollback) are opt-in

- **Status:** Accepted

## Context

Roadmap point 12c calls for hardening the deploy path against supply-chain attacks: the stack
pulls external images, three of them by a moving tag (`tecnativa/docker-socket-proxy:latest`,
`adguard/adguardhome:latest`, `tailscale/tailscale:latest`). A moved or poisoned tag ships new
code into a privileged, host-networked stack with no checkpoint. We also had no automatic recovery
when a new version comes up unhealthy.

The deploy path (`manage.sh` → `rebuild` → `docker compose up -d`) is the one surface a bug cannot
be unit-tested against — a mistake here shows up as a broken `./manage.sh update` on a live host,
not a failing test. That risk shapes the decision.

## Decision

Add three gates as a **standalone, opt-in** script (`scripts/supply-chain.sh`) surfaced through
new `manage.sh` subcommands (`pin`, `verify`, `health`, `safe-rebuild`). The subcommands are
terminal passthroughs; **the normal `update`/`rebuild` flow is unchanged and never calls them**,
so nothing here can break a deploy until the operator deliberately turns it on.

- **Digest pinning** — `pin` resolves each external image to an immutable `@sha256:` digest and
  writes `docker-compose.pinned.yml` + `images.lock`. The operator activates the pins by setting
  `COMPOSE_FILE=docker-compose.yml:docker-compose.pinned.yml` in `.env`; `pin` is re-run
  deliberately to move to newer images. Build services (`api`, `ui`, `dnsmasq`, `turbotunnels`)
  are pinned by their source commit, not a registry digest.
- **cosign verify** — `verify` checks the images listed in `cosign-policy.txt` (keyless identity
  or public key). Inert when the file is absent or `cosign` is not installed; a `.example` ships.
  Only images that publish signatures can be verified — the rest rely on digest pinning.
- **Health-gated rollback** — `safe-rebuild` snapshots the current pins, rebuilds, then polls
  `/health`; on failure it restores the previously-pinned digests and rebuilds again
  (automatic, non-destructive), then prints the exact `git reset` to roll the code back. It never
  resets the repo on its own.

## Consequences

- (+) A moved external tag can no longer silently enter the stack once pins are enabled.
- (+) A bad update can self-recover at the image layer without manual digging.
- (+) Zero blast radius by default — the feature is inert until opted in, honoring "don't break
  the deploy path."
- (−) Pins are host-generated state (gitignored), so each host runs `pin` itself and must re-run
  it to take upstream security patches — pinning trades auto-patching for immutability.
- (−) cosign coverage is partial (not every image is signed); digest pinning is the baseline.
- (−) The code-level rollback is operator-confirmed, not automatic, because an untested
  `git reset --hard` in the deploy path is itself a fire risk. Related:
  [0006](0006-fleet-agent-mtls-and-signed-releases.md), [0001](0001-host-networked-privileged-api-with-socket-proxy.md).
