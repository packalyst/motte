# Contributing

Thanks for helping improve the panel. This is a security appliance, so the bar is a little
higher than a typical app — the short version is below; the full, source-grounded rules live in
**[`docs/reference/coding-standards.md`](docs/reference/coding-standards.md)**. Read that before
a non-trivial change.

## The non-negotiables

1. **Security first.** The firewall, the at-rest encryption, and the VPN-only admin plane *are*
   the product. A refactor that weakens an invariant in `coding-standards.md` §3 is a
   regression, not a cleanup.
2. **Comment the WHY.** Every non-obvious line — especially a firewall rule or a fail-open
   branch — says *why it must be that way and what breaks otherwise*. Match the house style.
3. **No dead code, no copy-paste.** The advisory `deadcode`/`dupl` scanners back this up.

## Project layout

- `api/` — Go backend (packages under `api/internal/<domain>`, one concern each; entrypoint
  `api/cmd/main.go`). Routes are declared in `api/configs/endpoints.json`.
- `ui/` — Svelte 5 (runes) frontend; one view per page under `ui/src/views`.
- `agent/` — the fleet agent (separate Go module).
- `containers/` — the helper images the panel builds (`dnsmasq`, `turbotunnels`).
- `docs/reference/` — the full reference manual. `docs/adr/` — architecture decision records.
  `docs/todos/` — the backlog.

## Dev loop

```sh
./manage.sh rebuild        # regenerate config + build/run the stack from your .env
cd api   && go build ./... && go vet ./... && gofmt -l . && go test ./...
cd agent && go build ./... && go vet ./... && gofmt -l . && go test ./...
cd ui    && npm ci && npm run build
```

`gofmt -l .` must print nothing. CI runs exactly these as **blocking** checks; the security &
quality scanners (gosec, govulncheck, Trivy, CodeQL, dead-code, dup, npm audit) run as
**advisory** — fix what they flag where you touch it, and a scanner graduates to blocking once
it's clean repo-wide.

## Architecture decisions

Significant or non-obvious design choices are recorded as ADRs under
[`docs/adr/`](docs/adr/). If your change makes or reverses such a decision, add or supersede an
ADR in the same PR.

## Commits & PRs

- **Conventional-commit** style, concise, no chatter or emoji: `type(scope): summary`
  (`fix(firewall): …`, `feat(dhcp): …`, `docs(adr): …`).
- One logical change per commit; keep it building and green at each step.
- Describe the *why* and the user-visible effect in the PR; link the ADR if there is one.

## License

By contributing you agree your contributions are licensed under the project's
[AGPL-3.0](LICENSE).
