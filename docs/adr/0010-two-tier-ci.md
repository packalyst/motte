# 0010 — Two-tier CI: blocking green checks + advisory scanners

- **Status:** Accepted (2026-10-17)

## Context

The project had no CI. Adding a full security/quality suite (gosec, govulncheck, Trivy, CodeQL,
staticcheck, deadcode, dupl, npm audit, gitleaks, hadolint) all at once as **required** checks
would turn the pipeline red on the first run — base-image CVEs and pre-existing lint are a near
certainty — and block every merge until a large backlog is cleared. That punishes turning on
tooling, which is the wrong incentive.

## Decision

Split CI into two tiers:

- **Blocking** (`ci.yml`): `go build` / `go vet` / `gofmt` / `go test` for both modules, and the
  ui `vite build` — the exact commands already verified green, so the gate is meaningful from day
  one.
- **Advisory** (`security.yml` + GitHub's default CodeQL setup): every scanner runs on each push/PR and weekly, and
  **reports** findings (`continue-on-error`) without failing the build. A scanner is **promoted**
  into the blocking tier (drop `continue-on-error`, move the job) once it runs clean repo-wide.

## Consequences

- (+) Green on day one; findings are visible immediately and can be burned down deliberately.
- (+) The ratchet only tightens — nothing silently regresses once a check is promoted.
- (−) Until promoted, an advisory finding can land on `main` — triage discipline matters.
- (−) GitHub-only: these workflows can't be exercised in the local sandbox, so the first push is
  where runner-specific quirks surface.
- Related: [CONTRIBUTING](../../CONTRIBUTING.md).
