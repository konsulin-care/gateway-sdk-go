# ADR 012: Forward-Compatible Decoding, Fail-Closed Selection

**Status:** Accepted
**Date:** 2026-10-23
**Deciders:** Konsulin central

## Context

The gateway contract evolves additively: the hardening wave added two
event purposes (`payment-required`, `service-receipt`), the delivery claim
`payment_id`, the receipt fields `quota_remaining`/`body`, and new
`GW-*` codes (`GW-RATE-001`, `GW-IDX-011`, `GW-STS-005`,
`GW-HOOK-006/008/009`). A decoder that rejects anything it has never seen
breaks consumers on every additive gateway release; a *verifier* that
accepted anything about identity — which key, which token kind — would be
a downgrade hole (RFC 8725, PROPOSAL §8). Data and identity must be
decoded in opposite directions.

## Decision

- **Unknown data is ignored, not fatal.** Decoding a gateway JSON body or
  a verified token's claim set tolerates unknown fields and unknown claim
  names: they are skipped, never an error and never a deny
  (SDK-WIRE-004).
- **Unknown codes classify, not error.** A response code is looked up
  with `wire.LookupCode`; a code the catalog does not define falls back
  to status-based retry classification (429/502/503/504 retryable, the
  SDK-RETRY-002 classes) instead of failing the decode
  (`wire.Retryable`).
- **Unknown selection inputs deny.** Forward compatibility never extends
  to selection: an unknown or missing `typ` fails exact-match per the
  Token Kinds row, and an unknown `kid` gets one rate-limited JWKS
  refetch, then denies (ADR-007). A new gateway-signed kind or purpose
  is only accepted after this module adds it — an additive change here,
  shipped in a release, not a runtime tolerance.
- Additive contract changes land as new constants/entries in `wire`
  within a v0 minor (ADR-009); wire-shape breaks follow the same policy.

## Consequences

**Positive:**
- New gateway fields, claims, purposes, and error codes flow through old
  SDK versions without decode failures — consumers upgrade on their own
  schedule within v0.
- The security posture is unchanged where it matters: tolerance applies
  only to data about *what* was sent, never to identity (which key) or
  kind (which token).
- Retry classification degrades to status classes instead of erroring on
  an unknown code, so a brand-new gateway code never wedges a client.

**Negative:**
- Unknown claims are silently dropped rather than surfaced, so a consumer
  that wants a new claim must upgrade `wire` to see it typed — accepted;
  raw access remains available through the verified claim map.
- An unknown `typ`/`kid` denial means a gateway feature that introduces a
  new kind or signing key requires an SDK release before anything
  verifies — fail-closed by design (ADR-007), but it couples new token
  kinds to the SDK cadence.
