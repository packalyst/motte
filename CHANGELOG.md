# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project is pre-1.0, so dated
releases will be tagged as they are cut.

## [Unreleased]

### Added
- **DHCP / managed private networks** — the panel can gateway an isolated LAN segment: a
  DHCP-only `dnsmasq` sidecar, interface addressing via a panel-owned netplan drop-in brought up
  scoped (never a global `netplan apply`) with validate → health-check → rollback, MAC-keyed
  DHCP clients with auto/approve registration, and default-deny VPN reachability via a new nft
  table (internet-out NAT off by default). New **Networks** page.
- **"Firewall not active" warning** surfaced in the UI when the firewall layer fails to start,
  instead of only a boot log line.
- **CI/CD & supply-chain**: blocking CI (build/vet/gofmt/test + ui build), advisory security &
  quality scanners (gosec, govulncheck, staticcheck, deadcode, dupl, Trivy, gitleaks, hadolint,
  npm audit), CodeQL, and Dependabot across both Go modules, the ui, Actions, and Dockerfiles.
- **Project governance**: AGPL-3.0 `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, this changelog,
  `.editorconfig`, and architecture decision records under `docs/adr/`.

### Changed
- Grouped the panel-built helper images (`dnsmasq`, `turbotunnels`) under `containers/`; the
  repo root now holds only the first-class modules (`api`, `ui`, `agent`).
- Update flow now prunes dangling images after a successful rebuild so repeated updates don't
  fill the disk (dangling-only; tagged/in-use images, volumes and build cache are untouched).

### Fixed
- **vpn**: virtual-IP targets inside the VPN range are rejected (a mis-pointed quarantine could
  otherwise cut off an unrelated peer); DNS-name collisions are detected instead of stacking
  duplicate AdGuard rewrites; established flows for a newly-isolated peer are flushed from
  conntrack so isolation takes effect immediately; Headscale host names are made unique.
- **auth**: with `TRUSTED_PROXIES` unset the panel now falls back to `TRAEFIK_CONTAINER_IP`, so
  the per-IP login rate-limit no longer collapses into one global bucket.

### Security
- **firewall**: the Cloudflare-only and API-port gates keep their last-known state on a transient
  DB read error instead of failing open; global IPv6 is dropped on any interface, not just WAN.
- **setup**: the first-run Headscale connection test blocks SSRF to link-local/metadata even when
  reached via a hostname that resolves there.
- **fleet**: an agent's client certificate is revoked on uninstall, killing its mTLS access
  immediately rather than at cert expiry.
- **backup**: passphrase sealing hardened to Argon2id with a passphrase floor + generator.
- **vpn**: the generated Headscale policy is aligned with the nftables data-plane gate (no
  blanket wireguard-network grant; allow_all peers get the matching inbound rule).
