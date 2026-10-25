# 0008 — DHCP: scoped `ip addr` + netplan drop-in, reachability in nft

- **Status:** Accepted (2026-10-17)

## Context

The DHCP "managed private networks" feature makes the panel the gateway for an isolated LAN
segment: it must give a host interface an address, run a DHCP server on it, and control what that
segment can reach. Several ways to go wrong: a global `netplan apply` can bounce *all* host
networking (including the admin plane) and strand the operator; a full dnsmasq could hijack DNS;
and an unmanaged segment could route straight into the VPN.

## Decision

- **Addressing:** bring the interface up with a **scoped `ip addr replace`** for the immediate
  effect, and persist it with a **panel-owned netplan drop-in** — never a global `netplan apply`.
  Apply is guarded: validate → health-check → **rollback** on failure. Host filesystem/netplan
  writes go through `nsenter -t 1` because the `api` has its own mount namespace.
- **DHCP only:** the `dnsmasq` sidecar runs with `port=0` (DHCP, no DNS), config validated with
  `dnsmasq --test` before reload; reload is a container restart (no docker-exec).
- **Reachability:** a default-deny nft table (`motte_dhcp_net`) governs segment↔VPN reach; internet
  egress NAT is **off by default**.

## Consequences

- (+) A bad DHCP change can't strand the operator or knock out the admin plane; it rolls back.
- (+) No DNS hijack; reachability is enforced at the authoritative gate ([0002](0002-nftables-is-the-gate-headscale-acl-advisory.md)).
- (−) Host plumbing (netplan/dnsmasq/live DHCP) can only be fully verified on a deployed host, not
  in the build sandbox — the generated nft ruleset *is* checkable with `nft -c` and is.
- (−) More moving parts (a sidecar, two shared volumes, a netplan drop-in) for the update flow to
  carry.
