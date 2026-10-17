# 0011 — Remove docker-exec (`EXEC=1`) by moving Headscale ops off the CLI

- **Status:** Proposed

## Context

The Docker socket-proxy ([0001](0001-host-networked-privileged-api-with-socket-proxy.md)) is
started with `EXEC=1`, which permits `docker exec` into containers. Container exec is a powerful
verb — it is effectively "run arbitrary commands in another container" — and shrinking the
proxy's allowlist shrinks the blast radius of a compromised `api`. A review found only a small
number of call sites actually use exec, all of them Headscale operations invoking the `headscale`
CLI inside its container.

## Decision (proposed)

Move Headscale operations from `docker exec … headscale …` to Headscale's **REST API** and drop
`EXEC=1` from the socket-proxy. Of the three current exec call sites, two are a bootstrap
chicken-and-egg (the API key needed to call REST is itself created via exec on first run) and
need a migration plan — e.g. a one-time bootstrap that provisions the key, after which all
subsequent calls use REST, letting `EXEC` be disabled in steady state.

## Consequences

- (+) Removes the most dangerous verb from the proxy allowlist; a compromised `api` can no longer
  exec into siblings.
- (−) Requires solving the first-run key bootstrap without exec, or scoping exec to only that
  one-time step.
- (−) Ties the panel to the Headscale REST surface for these operations.
- **Open** — not yet implemented; tracked so the decision isn't lost. Related:
  [0001](0001-host-networked-privileged-api-with-socket-proxy.md).
