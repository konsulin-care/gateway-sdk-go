# ADR 015: Key Parsing Helpers (SDKP-006, amends ADR-006)

**Status:** Accepted
**Date:** 2026-10-25
**Deciders:** Konsulin central

## Context

The backend adopting the SDK must turn environment values (the gateway's
`cmd/genkey` output) into signers and publishable JWKs. Without shared
helpers every consumer hand-rolls base64 decoding and key parsing, with no
shared test vectors and no shared rule about what a parse error may say.
ADR-006 (Caller Key Custody) already bans the SDK from generating,
storing, rotating, serializing, or logging private keys — parsing
caller-supplied input is not custody, but the boundary must be written
down so the helpers cannot drift into key management. One decision pins
the accepted input formats, the derivation outputs, and the error rule.

## Decision

**This ADR amends ADR-006.** ADR-006's custody rule is unchanged and
still normative: the SDK never generates, stores, rotates, serializes, or
logs private keys. This ADR adds the narrow parsing carve-out: the SDK
parses *caller-supplied* key strings and returns in-memory keys to the
caller — parsing is not custody, and everything ADR-006 forbids remains
forbidden.

- **Allowed parse formats** (the only inputs the helpers accept):
  1. **Ed25519 private key** (`auth.ParseEd25519PrivateKey`): standard
     (padded) base64 wrapping either a 32-byte seed or an already-expanded
     64-byte private key — the gateway `cmd/genkey` output format. A seed
     is expanded with `ed25519.NewKeyFromSeed`. Trailing line breaks from
     the generator output are tolerated.
  2. **X25519 private key** (`envelope.ParseX25519PrivateKey`): standard
     (padded) base64 wrapping exactly 32 bytes. Trailing line breaks are
     tolerated.
  3. Anything else — malformed base64, any other decoded length, truncated
     input — **fails closed**: rejected with an error, never a partial or
     guessed key.
- **Derivation outputs.** From a parsed key the SDK derives the public
  key, the `kid` as the RFC 7638 thumbprint of the *public* key (never a
  configured value, never derived from private material — ADR-006), and
  for X25519 the `use:enc` JWK (`envelope.EncJWK`: kty OKP, crv X25519,
  use `enc`, x the base64url public coordinate) for publishing in the
  party JWKS.
- **No input in errors.** Parse errors carry only format and length facts
  (e.g. "decoded length is N bytes, want 32") — never the input string,
  never decoded key material. Key material is never logged anywhere in
  the SDK (ADR-006 logging rule).
- **Test vector.** A golden test pins genkey-format input → public key,
  `kid`, and JWK against fixed expectations, so format drift is caught
  offline (ADR-004 governs mirrored vectors; this fixture is SDK-owned).

## Consequences

**Positive:**
- One accepted format per key type, one error rule: consumers parse env
  values the same way the SDK's own fixtures do, and malformed input
  fails closed at the boundary.
- The custody line is explicit: parsing caller-supplied bytes and
  deriving public outputs is allowed; generation, storage, rotation, and
  logging are not — reviewable against a single document.
- Errors are safe to log by construction: they describe format and
  length only, so no debug log can leak key material.

**Negative:**
- Two helper homes (`auth` for Ed25519, `envelope` for X25519) instead of
  one key-parsing package — accepted to keep `envelope` free of signing
  concerns and `auth` free of JWE concerns (ADR-005 import rules).
- The format list is closed: a future key format or encoding needs an
  amendment here, not an ad-hoc parser — intentional friction.
