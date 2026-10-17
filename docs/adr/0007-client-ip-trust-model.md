# 0007 — Real client IP via trusted-proxy + CF-Connecting-IP, fail-closed

- **Status:** Accepted (recorded retroactively; hardened 2026-10-17)

## Context

The panel sits behind Traefik, and usually behind Cloudflare too. Security controls key on the
client IP — per-IP login rate-limiting, audit logs, the Cloudflare-only firewall gate. If the
panel naively trusts `X-Forwarded-For`, any client can spoof its IP and defeat those controls; if
it naively trusts the socket peer, every request looks like it came from the proxy and the per-IP
controls collapse into one global bucket.

## Decision

`GetClientIP` trusts a forwarded header **only when the immediate peer is a trusted proxy**
(`TRUSTED_PROXIES`), and prefers `CF-Connecting-IP` when the trusted hop is Cloudflare. When
`TRUSTED_PROXIES` is unset, it **falls back to `TRAEFIK_CONTAINER_IP`** (added 2026-10-17) so the
default deployment still distinguishes clients instead of bucketing them together. Untrusted
hops' forwarded headers are ignored — the model **fails closed** toward the socket peer.

## Consequences

- (+) Spoofed `X-Forwarded-For` from an untrusted client is ignored; real per-IP controls work in
  the default topology without extra config.
- (−) A misconfigured `TRUSTED_PROXIES` (too broad) would re-enable spoofing — it must list only
  the real proxy hop(s).
- (−) An exotic topology (extra proxy layers) still needs `TRUSTED_PROXIES` set explicitly.
- Related: [0002](0002-nftables-is-the-gate-headscale-acl-advisory.md).
