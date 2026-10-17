# 0009 — Degrade (don't crash) on subsystem init failure; surface it

- **Status:** Accepted (recorded retroactively; UI signal added 2026-10-17)

## Context

The panel wires up several subsystems at boot (firewall, WireGuard, Headscale, stats, fleet). If
any one failing hard-crashed the process, a single transient problem (say, a slow Headscale) could
take the whole admin plane offline — including the very UI an operator needs to *fix* it. But the
opposite failure mode is worse for a security appliance: silently running with the firewall
*down* and no one noticing.

## Decision

Subsystem init failures **degrade rather than crash**: the api stays up so the operator can log
in and remediate. But a failure that weakens security is **surfaced**, not just logged — e.g. a
firewall that fails to activate now raises a **"firewall not active" warning in the UI**
(added 2026-10-17), not only a boot log line. Security-sensitive gates that depend on state
(Cloudflare-only, API-port) **fail closed** on a transient read error (keep last-known-restrictive
state) rather than fail open.

## Consequences

- (+) A transient subsystem problem never locks the operator out of the tool that fixes it.
- (+) A down firewall is loud, not silent.
- (−) "Stay up and warn" means the operator must actually act on the warning — the panel can run
  degraded.
- Related: [0001](0001-host-networked-privileged-api-with-socket-proxy.md), [0007](0007-client-ip-trust-model.md).
