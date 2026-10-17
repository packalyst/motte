# Security Policy

This project is a **security appliance** — a VPN/firewall admin panel. Vulnerabilities here can
expose a network, so they are taken seriously and handled privately until fixed.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private reporting:

1. Go to the repository's **Security** tab → **Report a vulnerability** (GitHub Private
   Vulnerability Reporting), or
2. Open a **draft security advisory** under **Security → Advisories**.

Please include: affected component (api / ui / agent / a container), version or commit, a clear
reproduction, the impact, and any logs or PoC. If you have a fix in mind, say so — a patch is
welcome but never required to report.

## Scope

In scope: the `api` backend, the `ui`, the fleet `agent`, the helper containers, the nftables
and WireGuard/Headscale handling, authentication/session/2FA, the at-rest encryption and backup
sealing, and the fleet mTLS/signed-release chain.

Out of scope: issues that require an already-root operator on the host (the panel runs
privileged by design — see `docs/reference/architecture.md`), third-party upstreams (report
those upstream), and self-inflicted misconfiguration that only affects the operator's own box.

## What to expect

- **Acknowledgement** of a valid report as soon as it's triaged.
- A fix developed privately, with credit to the reporter unless anonymity is requested.
- **Coordinated disclosure**: the advisory is published once a fix is available.

## Security posture (context for researchers)

Two invariants run through the codebase and are the first thing to check a finding against:

- **The firewall is the gate** — default-drop, and it fails *open* only where a lock-out would
  otherwise be possible; every such branch is commented with its rationale.
- **Secrets are encrypted at rest** (AES-256-GCM) with a safe key-rotation path; backups are
  sealed with Argon2id and carry secrets as plaintext only *inside* the sealed body.

The threat model, access-control layers, and crypto details are documented in
[`docs/reference/security.md`](docs/reference/security.md).
