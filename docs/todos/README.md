# Follow-ups

Agreed-but-not-yet-built work: one file per follow-up, so nothing gets lost between
sessions. These are committed to the repo, so **keep them free of sensitive info** — no
keys, tokens, passwords, private IPs, or hostnames. Describe *what* and *why*, not secrets.

## Convention
- One `.md` per follow-up, named after the thing (`kebab-case`).
- Start with a one-line summary, a **Status** (Open / In progress / Done), and a **Priority**.
- Say what triggers doing it (the condition that makes it worth the effort), the plan, and
  the trade-offs. Link related follow-ups.
- When done, either delete the file or flip **Status: Done** with the commit that closed it.

## Index
- [drop-exec-headscale-rest.md](drop-exec-headscale-rest.md) — remove docker-socket-proxy
  `EXEC=1` by moving the 3 headscale-CLI calls to REST (closes the lateral-to-root path).
- [sshd-config-drop-in.md](sshd-config-drop-in.md) — mount only `/etc/ssh/sshd_config.d/` into
  the api container instead of the whole SSH config.
- [session-token-httponly-cookie.md](session-token-httponly-cookie.md) — move the session
  token out of localStorage into an HttpOnly cookie (needs CSRF handling; low prio post-XSS-fix).
- [agent-release-signing.md](agent-release-signing.md) — sign release assets so a compromised
  GitHub pipeline can't ship a malicious agent (defends beyond the current sha256 pinning).
