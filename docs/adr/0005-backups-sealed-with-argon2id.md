# 0005 — Backups sealed with Argon2id; plaintext secrets only inside the seal

- **Status:** Accepted (recorded retroactively; hardened 2026-10-17)

## Context

An operator must be able to export a portable backup and restore it on another box — including on
a fresh install that does **not** have the original `ENCRYPTION_SECRET`. So the backup can't rely
on the at-rest key ([0004](0004-secrets-encrypted-at-rest-with-rekey.md)); it needs its own
passphrase-based protection, and that protection must resist offline brute force.

## Decision

A backup is **sealed** with a key derived from an operator passphrase via **Argon2id** (memory-
hard KDF), then authenticated-encrypted. Inside the sealed body, secrets are carried as plaintext
so a restore can re-encrypt them under the *destination's* key. A passphrase **floor** is
enforced and a strong-passphrase **generator** is offered, so the seal isn't trivially weak.

## Consequences

- (+) Portable, host-independent restore; the file on disk is useless without the passphrase.
- (+) Argon2id makes offline guessing expensive even for a weak-ish passphrase.
- (−) A forgotten passphrase means an unrecoverable backup — by design.
- (−) The plaintext-inside-the-seal design means the *unsealed* intermediate must never be
  written to disk; it stays in memory during restore.
- Related: [0004](0004-secrets-encrypted-at-rest-with-rekey.md), [0003](0003-sqlite-source-of-truth-firewall-rebuilt-from-db.md).
