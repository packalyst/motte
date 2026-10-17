# 0001 — Host-networked, privileged `api` with a Docker socket-proxy

- **Status:** Accepted (recorded retroactively, 2026-10-17)

## Context

The panel's job is to manage the *host's* networking: the WireGuard interface, the nftables
ruleset, routes, and (now) DHCP interfaces. It also needs to read host logs/journald and manage
a few sibling containers. A normal bridge-networked container cannot do any of this.

## Decision

Run the `api` container `network_mode: host`, `pid: host`, `privileged: true`, with `NET_ADMIN`.
It therefore runs `nft`, `ip`, `wg` directly against the host, and uses `nsenter -t 1` for
operations that need the host's mount/systemd view (journald, netplan). Docker is **not** reached
via the raw socket; a **`docker-socket-proxy`** sits in front with a per-verb allowlist
(`CONTAINERS`, `INFO`, `POST`, `IMAGES`, `EXEC`), and the api talks to it over `tcp://127.0.0.1`.

## Consequences

- (+) The panel can actually do its job (firewall, VPN, DHCP) without brittleness.
- (+) The socket-proxy shrinks the Docker blast radius versus mounting the raw socket.
- (−) A compromise of the `api` is a host compromise — this is inherent and is why the auth
  plane, at-rest encryption and firewall discipline are strict.
- (−) `EXEC=1` on the proxy still allows container exec; narrowing it is tracked in [0011](0011-drop-docker-exec.md).
- Related: [0002](0002-nftables-is-the-gate-headscale-acl-advisory.md), [0009](0009-degrade-dont-crash-on-subsystem-init.md).
