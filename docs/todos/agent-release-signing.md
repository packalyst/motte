# Agent release signing

Sign the agent release assets so integrity no longer rests entirely on trusting the GitHub
release. Today everything is sha256-pinned/verified, which stops MITM and mirror tampering —
but NOT a compromised GitHub release pipeline, where an attacker replaces the binary **and**
`checksums.txt` with matching values and every check still passes.

- **Status:** Open
- **Priority:** Low for a solo operator with a private repo (see "When to do it"); Medium+
  if the repo's trust boundary widens.

## Threat it closes
A signature can only be produced with a private key kept OFF GitHub. The agent/installer
carry the matching public key and verify the signature before trusting `checksums.txt`. An
attacker who owns the GitHub release but not the signing key can no longer ship a valid
malicious update.

## What it does NOT close
- The signing key leaking (then you're back to square one — key hygiene is the whole game).
- The very first `install.sh` fetch: the script itself comes from GitHub, so a compromised
  pipeline could strip the check from it. The first install must be trusted out-of-band
  (the panel's self-extractor, which the panel already verified, is the practical anchor);
  the Go agent then verifies subsequent self-updates with its embedded public key.

## Plan (minisign / Ed25519)
1. Generate a keypair ONCE (operator, on a trusted machine — never in CI logs or the repo).
   Public key is committed/embedded; private key is stored safely (password manager or a
   passphrase-protected local file), used only at release time.
2. Release step: after building, `minisign -S -m checksums.txt` → upload `checksums.txt.minisig`.
3. Embed the public key: a new `agent/verify.go` (pure-Go `crypto/ed25519`) + a variable in
   `agent/install.sh`.
4. Verify before trusting `checksums.txt` in the three spots that currently trust it blindly:
   `agent/manifest.go`, `agent/install.sh`, and `api/internal/fleet/agentcache.go`.

## Operational cost
Every agent release then needs the private key present to sign — releases can no longer be
cut without it. That recurring "the key must be there to release" is the real tax.

## When to do it
Worth building if the GitHub repo becomes a SEPARATE trust boundary from the panel — public
repo, multiple maintainers, shared CI tokens, or distribution to hosts you don't control.
For a single operator + private repo, "compromise the release pipeline" ≈ "compromise the
GitHub account", so the cheaper equivalent mitigation is **2FA + a hardware key on the GitHub
account** and tight release-write access. Revisit signing if that trust boundary changes.

## Related
- Agent supply chain is otherwise solid: sub-tool downloads are sha256-verified fail-closed,
  the panel caches a checksum-verified binary, mTLS pins the panel CA, enrollment pins the CA
  fingerprint. This follow-up only addresses the compromised-source-of-truth case.
