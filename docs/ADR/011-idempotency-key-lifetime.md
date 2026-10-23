# ADR 011: Idempotency-Key Lifetime

**Status:** Accepted
**Date:** 2026-10-23
**Deciders:** Konsulin central

## Context

Creates carry an `Idempotency-Key` the gateway dedupes per logical
operation (SDK-CLIENT-002, SDK-RETRY-001). The gateway hardening contract
added two codes that pin the lifetime from the other side: `402
GW-HOOK-006` (entitlement/quota exhausted — terminal, and the payment or
top-up makes the retry a *new* operation) and `422 GW-HOOK-008`
("Idempotency-Key replayed with a different request body"). Two failure
modes pull opposite ways: rotating the key while retrying one logical
create turns it into several operations; holding the same key after the
operation's outcome is decided collides with the gateway's stored first
result. One normative rule must cover both.

## Decision

- **Stable across transport retries.** One logical create keeps the same
  `Idempotency-Key` across every attempt of that create — network errors,
  `429`, `502/503/504`, and the in-flight replay `409 GW-API-002`
  (`idempotency_in_progress`) all reuse it (SDK-RETRY-002). Each attempt
  still signs a fresh `jti` (ADR-008): the key identifies the operation,
  the `jti` identifies the attempt.
- **New key after a terminal 402.** A `402 GW-HOOK-006` decides the
  operation's outcome: entitlement or provider quota must be fixed first,
  then the call runs again as a **new** operation with a **new**
  `Idempotency-Key` (`wire.RequiresNewIdempotencyKey`, SDK-RETRY-003).
  There is no park-and-resume under the old key.
- **New key on any body change.** If the request body differs in any way,
  it is a different operation and must never reuse the key — the gateway
  answers `422 GW-HOOK-008` otherwise (ADR-012 makes unknown fields
  harmless, not body edits).
- **Caller-supplied keys follow the same rule.** The SDK generates a key
  only when the caller supplies none; a caller-supplied key is sent
  as-is, and the caller owns the same stability/newness obligations.

## Consequences

**Positive:**
- The gateway's idempotency store collapses honest retries into one
  operation and never aliases two distinct creates — the two hardening
  codes become mechanically enforceable from the SDK side.
- The rule is decidable inside `client`: 402 and body divergence are the
  only two events that end a key's life; everything else reuses it.
- Retry tests can assert the boundary exactly (`SDK-RETRY-C01`: same key
  across a 409→200 replay, new key after a 402).

**Negative:**
- Callers supplying their own keys must follow the same rule or see
  `GW-HOOK-008`; this is documented but not enforceable by the SDK.
- The 402→pay→retry flow is caller-driven (the SDK cannot top up quota),
  so a mis-classified 402 would strand a logical create — mitigated by
  the catalog-driven classification (`wire.Retryable`,
  `wire.RequiresNewIdempotencyKey`) instead of hand-kept lists.
