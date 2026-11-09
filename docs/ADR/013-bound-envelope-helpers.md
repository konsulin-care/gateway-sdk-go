# ADR 013: Bound Envelope Helpers (SDKP-001)

**Status:** Accepted
**Date:** 2026-10-24
**Deciders:** Konsulin central

## Context

The gateway's normative Bound Envelope convention (SDKP-001) seals an
application payload inside a JWE whose plaintext is a wrapper
`{v, from, to, service, iat, nonce, data}`. `envelope.SealBound` and
`envelope.OpenBound` implement the seal/open side, but the wrapper checks
are more than a decrypt: identity fields must match caller expectations,
the wrapper must be fresh, the nonce must not replay, and the payload
must stay bounded. Each bound has a reason — a stale or future-dated
wrapper widens the replay surface, an unbounded nonce or data field is a
memory vector, and expectations sourced from caller strings rather than
the verified delivery token would let a caller assert values the token
never covered. One decision must pin the order, the windows, the caps,
the fixture's provenance, and the one new import edge this adds.

## Decision

- **Normative check order, fail closed, nil data on first failure.**
  `OpenBound` runs the SDKP-001 checks in this order: (1) the JWE
  decrypt per `Open`, (2) wrapper `v` supported (`v == 1`), (3) `to`
  equals the expectations, (4) `from` equals the expectations, (5)
  `service` matches, (6) `iat` freshness, (7) the nonce check, (8) the
  data cap. Errors carry only the check fact — never the wrapper values,
  the payload, or the plaintext — and a rejection always returns nil
  data, never a partial accept.
- **MaxAge: default 5 min, cap 15 min.** `envelope.DefaultMaxAge` is
  `5 * time.Minute` (applied when `Expectations.MaxAge` is zero) and
  `envelope.MaxMaxAge` is `15 * time.Minute`. A negative `MaxAge` or one
  above the cap fails closed in `effectiveMaxAge` — no caller can widen
  the freshness window past fifteen minutes.
- **60 s future skew.** The wrapper `iat` may be at most 60 s ahead of
  the clock (`maxIatFutureSkew`); an `iat` exactly `MaxAge` old or
  exactly 60 s ahead is still accepted — only values beyond the bounds
  deny.
- **Nonce retention = max(10 min, MaxAge + 60 s).** Step 7 reserves
  `(wire.ScopeNonce, from+"\x00"+nonce)` in the caller's `ReplayCache`
  until `now + max(10 min, MaxAge + 60 s)`: the freshness window plus
  the future-skew bound covers every wrapper the `iat` check could still
  accept, and ten minutes (`minNonceReplayRetention`) is the floor. The
  nonce rule is enforced before any cache consultation: an empty nonce
  or one longer than 64 characters fails closed, and the error names
  only the check fact, never the nonce. Distinct `(from, nonce)` pairs
  cannot collide because the key joins the two values with `\x00`, which
  cannot occur in either.
- **Data cap.** Step 8 rejects wrapper `data` larger than
  `maxBoundDataBytes` = 524288 bytes (512 KiB).
- **Expectations come from verified claims.**
  `ExpectationsFromClaims(verify.Claims)` derives `From = sub`,
  `To = aud[0]`, and `Service` from the already-verified delivery-token
  claims, so callers never pass values the token did not cover. It fails
  closed on an empty `service` or an audience count other than one.
- **envelope -> verify import edge.** Deriving expectations from
  `verify.Claims` makes `envelope` import `verify` — the one edge beyond
  `envelope`'s original allowed set (`wire`, `internal/jwk`). The edge is
  strictly one-directional: `verify` imports neither `envelope` nor
  `client`, so the import DAG stays acyclic and `verify`'s trust-layer
  posture (ADR-005) is unchanged.
- **Nil-cache semantics.** A nil `ReplayCache` opts out of nonce dedupe
  entirely: step 7 validates the nonce format, then skips the
  reservation. This is a documented caller choice (the caller owns key
  custody and can supply its own dedupe), not a silent default — with a
  non-nil cache the check is fail-closed, and any cache error denies.
- **Fixture provenance: SDK-owned, never mirrored.** The bound decrypt
  vector lives at `envelope/testdata/bound-v1-decrypt.json`, generated
  by the test-only deterministic seal path and regenerated with
  `go test ./envelope -run TestBoundDecryptVector -update`. It is an
  SDK-owned fixture: it never lives under `testdata/golden/`, which
  holds only the read-only mirrored gateway vectors (ADR-004), and no
  test reads any path outside this module.

## Consequences

**Positive:**
- The wrapper checks are decidable and testable at exact boundaries:
  the 5 min default, the 15 min cap, the 60 s skew, the
  `max(10 min, MaxAge + 60 s)` reservation, and the 512 KiB data cap
  each have one constant and one rule.
- Expectations derived from verified claims close the "caller-asserted
  identity" hole: `from`, `to`, and `service` are what the gateway-signed
  token actually covered.
- The `envelope -> verify` edge is one-way, so the module graph remains
  acyclic and `verify` never depends on envelope internals.
- The fixture is regenerable from in-repo code (`-update`), keeping the
  golden mirror strictly gateway-sourced (ADR-004).

**Negative:**
- A nil cache means two bound envelopes with the same `(from, nonce)`
  are not deduped — accepted as an explicit opt-out the caller must
  reason about, since replay protection then lives outside the SDK.
- The one-way import edge couples `envelope`'s public helper signature
  to `verify.Claims`; changing verified-claim shape now ripples into
  `envelope` — mitigated by `verify.Claims` being a plain claim struct.
- The deterministic fixture key and IV are test-only values; they must
  never be mistaken for production key material (they are never exported
  from test code).
