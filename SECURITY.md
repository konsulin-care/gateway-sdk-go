# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest `v0.x` tag | yes |
| older `v0.x` tags | best effort — upgrade to the latest tag |

## Reporting a vulnerability

Do **not** open a public issue or pull request. Report privately through
GitHub private vulnerability reporting: the repository **Security** tab →
**Report a vulnerability**. Include the affected version/tag, a
reproduction, the impact, and any suggested fix. Do **not** attach private
keys, production peppers, live tokens, or customer data — describe them
instead.

You will get an acknowledgement when the report is triaged. Confirmed issues
are fixed privately where warranted, then released with a `CHANGELOG.md`
entry and a new tag; non-actionable reports get a short explanation.

**Scope**: this SDK — the client, inbound verification, envelope, and the
conformance runner. Vulnerabilities in the Konsulin gateway belong to the
gateway repository's own disclosure channel.

## Security invariants

These are normative (AGENTS.md, PROPOSAL.md §8); every change — including a
security fix — must preserve them:

- **Fail closed**: any signature, `typ`, claim, audience, expiry,
  `body_sha256`, or envelope failure denies — never a partial accept, never
  a "verify best effort" mode.
- **Exact `typ`** per the Token Kinds row; a missing or generic `typ` fails
  even under a valid signature.
- **Kid-only key selection from JWKS only**: one rate-limited refetch per
  unknown `kid`, then deny. Keys never come from any other source.
- **Stdlib-only runtime**: no third-party imports from non-test code, so
  the dependency graph stays auditable in one page.
- **Never log secrets, bodies, tokens, keys, or the pepper.**
- **Key custody stays with the caller**: the SDK never generates, stores, or
  rotates production keys; encryption opens only through the caller's
  `Decrypter`, and plaintext pepper lives in memory only — never on disk or
  in the environment.
- **Transport**: `https` only; `WithInsecureTransport` exists for local
  dev/test and fails at construction in production posture.
- **Constant-time compares** for `body_sha256`, identity hashes, and any
  secret-derived byte comparison.
- **Replay protection**: `jti` and `webhook_id` are reserved atomically
  through the `ReplayCache` interface; any reservation error denies.

## Repository hygiene

- The gateway signing key is never mirrored; the golden
  `testonly-party-private.key` is a test-only vector key, useless outside
  `testdata/golden/`.
- No production pepper or credential is ever committed; tests use fixed,
  published test vectors only.
- `mise run qc --secret` scans every commit for accidental secret material
  and runs as part of the pre-commit hook and CI.
