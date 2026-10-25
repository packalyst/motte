# 0002 — nftables is the enforcement gate; the Headscale ACL is advisory

- **Status:** Accepted (recorded retroactively, 2026-10-17)

## Context

Reachability between VPN peers (and from peers to LAN/DHCP segments) could be enforced in two
places: the Headscale/Tailscale **policy** (control-plane ACL) or the host **nftables** ruleset
(data-plane). Relying on the control-plane alone means a policy-sync bug, a stale node, or a
direct packet can bypass the intended restriction.

## Decision

The **nftables ruleset is the authoritative gate**. Every reachability decision (peer isolation,
virtual-IP exposure, DHCP-network reachability) is expressed as a default-deny nft table
(`motte_vpn_acl`, `motte_dhcp_net`, …) rebuilt from the database. The Headscale policy is
generated to **match** the nft gate so the two agree, but it is treated as advisory UX, not as
the thing standing between a packet and a host.

## Consequences

- (+) A single, inspectable source of truth for "what can reach what"; validated with `nft -c`
  before apply.
- (+) Control-plane drift cannot silently open a path.
- (−) The nft and Headscale sides must be kept aligned deliberately — a 2026-10-17 fix corrected
  a case where the policy granted a blanket wireguard-network reach the nft gate did not.
- (−) Isolation changes must also flush conntrack, or an established flow outlives the rule (also
  fixed 2026-10-17).
- Related: [0003](0003-sqlite-source-of-truth-firewall-rebuilt-from-db.md).
