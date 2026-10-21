# ADR 007: Fail-Closed, Kid-Only Key Selection

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

The SDK verifies gateway-signed tokens (callbacks, tickets) and gateway JWKS
key substitution is a live threat class (PROPOSAL §8 threat model item 4).
The gateway ADR *Fail-Closed Security Posture* (gateway ADR-011) makes any
verification failure deny; the SDK's inbound path must hold the same posture,
including during key rotation and JWKS unavailability.

## Decision

**Any signature, `typ`, claim, audience, expiry, `body_sha256`, or envelope
failure denies — never a partial accept.** Concretely:

- **Kid-only key selection**: keys come from the JWKS only, selected by the
  token's own header `kid`. No alg-based key guessing, no "first key" fallback,
  no extra key-selection hints on outbound tokens (SDK-AUTH-001).
- **Unknown `kid`** → at most **one rate-limited JWKS refetch** inside the
  rate-limit window, then deny (SDK-VERIFY-001). Bounded refetch prevents
  refetch storms on garbage tokens.
- **Rotation**: the JWKS serves current + previous key (each `kid` its
  RFC 7638 thumbprint), so tokens signed before a rotation keep verifying
  during the gateway's grace window — no SDK config change follows a rotation.
- **Exact `typ`** per Token Kinds row; missing or generic `typ` fails even
  under a valid signature (RFC 8725 §3.11).
- **Expiry** with 60 s skew; `body_sha256` over the exact POST bytes, compared
  in constant time.
- **Replay**: single-use `jti` / `webhook_id` dedupe through `ReplayCache`
  (interface, in-memory default), atomic per key.
- JWKS cache TTL-based; a verification failure never downgrades to an
  unverified accept.

## Consequences

**Positive:**
- No ambiguity: a failure always means deny — eliminates the whole class of
  "allow on partial verification" bugs.
- Key substitution cannot succeed: only JWKS keys, only by `kid`, one bounded
  refetch.
- Rotation is transparent to callers — previous key keeps verifying while the
  gateway's grace window runs.

**Negative:**
- Transient JWKS unavailability plus an unknown `kid` denies the request;
  callers must retry — accepted (fail closed beats availability here).
- A hostile client can trigger at most one refetch per rate-limit window per
  unknown `kid`; bounded by design.
