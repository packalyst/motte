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
- [agent-release-signing.md](agent-release-signing.md) — sign release assets so a compromised
  GitHub pipeline can't ship a malicious agent (defends beyond the current sha256 pinning).
