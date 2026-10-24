# 0014 — Fleet browser console (interactive shell)

Status: Accepted
Date: 2026-10-20

## Context

Roadmap point 7 (ADR-0012): operators want an in-browser interactive terminal to a fleet machine —
the PuTTY/SSH replacement — without opening any inbound port on the host. The fleet agent already
dials out to a panel mTLS listener, but only polls a **strict command allowlist (never a shell)**,
which is a deliberate security strength. An interactive console is the opposite of that model, so it
needs its own transport and heavy, separate gating.

## Decision

Add an interactive console as a **new, opt-in, heavily-gated capability**, kept entirely separate
from the allowlist command path.

**Transport — two WebSocket hops bridged in-process:**
- The agent opens a **persistent outbound WebSocket** to the fleet mTLS listener (`GET /console`),
  authenticated by its enrolled **client certificate**, only while the console is enabled for the
  host. One channel multiplexes many sessions by id (tabs / multiple operators).
- The browser opens a WebSocket to the main API (`/api/fleet/console/ws`, mounted directly so the
  upgrade bypasses REST middleware; the handler authenticates the session itself). The panel relays
  frames between the browser and the machine's agent channel.
- Frame protocol (JSON; binary base64): `open/data/resize/close/file-put/file-get/file-chunk/
  session-exit/error`.

**Sessions** run inside `tmux new -A -s panel-<id>` on the agent (PTY via creack/pty), so a dropped
or reconnected browser **reattaches the same shell**; a bare login shell is the fallback if tmux is
absent. tmux's status bar is off (the panel shows the session). Under systemd the tmux server runs in
a transient scope of its own, so the shells also outlive an agent restart (an update, a port
change); only turning the console off (or a local-policy lock, or uninstalling) ends them, also when
it was turned off while the agent was down. A viewer joining a session someone else holds is shown
its current screen (a snapshot, cursor included) before live output.

**Gating (compensating controls for offering a real shell):**
- **Per-host enable, default OFF** — a `fleet_machines.console_enabled` column *and* an agent-side
  `ConsoleEnabled` flag; both must be on. The agent never opens the channel otherwise.
- **RBAC + scope** — operator+ to open, admin to enable; machine scope enforced (fleet/scope.go).
- **Step-up** — a one-time, short-lived grant minted after step-up re-auth is required before a
  WebSocket opens (the WS itself can't do the 428 dance). Normal grants are multi-use within a few
  minutes (so one step-up covers several tabs/reconnects); read-only share grants live ~30 min.
- **Audit** — enable/disable, grant issuance, and every session open/close.
- **Session recording** — optional per host; output is tee'd to an asciinema `.cast` + an audit
  entry.
- **Read-only share** — a view-only grant (input dropped server-side) handed via a `#fconsole=`
  deep link; the viewer must still be a logged-in panel user.
- Disabling the toggle or revoking the machine tears down live sessions immediately.

**WebAuthn/RP note:** none — this is unrelated to passkeys.

## Consequences

- A full interactive shell is a materially larger surface than the allowlist. The gating above is
  the mitigation, and the console stays separate from (and does not weaken) the allowlist path.
- The agent gains two dependencies (`creack/pty`, `gorilla/websocket`). The agent is released out of
  band (`make release`), so exercising the console end-to-end needs a new agent build.
- The panel keeps an in-memory registry of live agent channels (single process; not clustered).
- Recordings are written to `console_record_dir` (setting) — point it at a volume-backed path for
  durable audit.
