# 0004 — Secrets encrypted at rest (AES-256-GCM) with a rekey path

- **Status:** Accepted (recorded retroactively, 2026-10-17)

## Context

The database holds high-value secrets: WireGuard/Headscale keys, API tokens, 2FA material, fleet
signing material. If the DB file (or a backup of it) leaks, those must not be usable. A static
embedded key is not enough — operators need to rotate the key if it is ever exposed.

## Decision

Secret columns are encrypted with **AES-256-GCM** under a key derived from `ENCRYPTION_SECRET`.
The value stored is nonce + ciphertext + auth tag, so tampering is detected on read. A
**rekey path** (`manage.sh rotate-key` → `api --rekey-check` / rekey) re-encrypts every secret
under a new key, with a DB backup taken first and restored on failure, so rotation is safe to run
on a live install.

## Consequences

- (+) A stolen DB or backup yields ciphertext, not secrets.
- (+) Key compromise is recoverable without rebuilding state.
- (−) `ENCRYPTION_SECRET` becomes the one thing that must be backed up *separately* from the DB —
  losing it loses the secrets.
- (−) Every new secret-bearing column must go through the encrypt/decrypt helpers, not raw SQL.
- Related: [0005](0005-backups-sealed-with-argon2id.md).
