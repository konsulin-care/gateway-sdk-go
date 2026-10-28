# Phase 2 — Inbound Trust

## Objective

Make the SDK trustworthy on the inbound side: `verify` (JWKS cache with
bounded refetch, per-kind checks, callback middleware, the six Recipient
Verification Rules, `ReplayCache`), `identity` (normalization + gateway
`hashfmt` HMAC hashes), and `envelope` (compact JWE seal/open over X25519).
Exit: **SDK-VERIFY-C01, SDK-ID-C01, SDK-ENV-C01 green offline**.

## Ground rules

Each checklist item is one `SDK-*` behavior: the behavior, its accept/deny
expectation, and the test that proves it. TDD — write the named failing
test first, then implement. Every test below runs offline (`httptest` +
fixtures) and reads only in-module paths; the gateway checkout is an
authoring-time reference (AGENTS.md), never a test dependency. Re-run
`go test -race ./...` and `mise run qc` after each item.

## Depends on

- `docs/tasks/.archive/01-foundation-test-kit.md` (landed: `internal/jws`,
  `internal/jwk`, `wire` constants/error catalog, `gatewaytest` minter +
  deterministic `ReplayCache` + manifest verifier).

## Decisions (agreed in discussion)

1. **`internal/jwk`**: `ParseKey`/`ParseJWKS` additionally accept OKP/X25519
   keys only when `use` is `enc` (`alg` absent or `ECDH-ES`); X25519 without
   `use:enc` is rejected. `KeySet.ByKid` was split into `SigByKid` (Ed25519/
   P-256 only, never X25519) and `EncByKid` (X25519 `use:enc` only); an empty
   kid matches nothing. Thumbprints work for X25519 over `crv`,`kty`,`x`.
   `envelope` may import `internal/jwk` (never `internal/jws`); no jwk type is
   re-exported.
2. **`verify.ReplayCache`**: `Check(ctx, scope, key string, until time.Time)
   (bool, error)` atomically reserves; `Release(ctx, scope, key string)
   error` frees. Scopes `jti` and `webhook_id`; any `Check` error denies.
   In-memory default (`NewMemoryReplayCache`) is concurrency-safe and evicts
   after `until`. Retention: `jti` until `exp`+60 s; `webhook_id` until
   `max(exp+60s, now+retention)`, default 24 h via `WithReplayRetention` (the
   gateway re-mints delivery tokens per retry with the same `webhook_id`).
   The `gatewaytest` fake satisfies this interface; the compile-time
   assertion lives in `gatewaytest/replay_test.go` (non-test `gatewaytest`
   never imports `verify`, avoiding cycles with verify tests).
3. **`verify.NewVerifier(jwksURL, self string, opts...)`** with
   `WithHTTPClient`, `WithTTL` (default 5 m), `WithRefetchInterval` (default
   30 s), `WithClock`, `WithReplayCache`, `WithReplayRetention`; `iss` must be
   `gateway`. JWKS cache: kid-only via `SigByKid`, TTL refresh, one refetch
   per unknown kid under a single global rate-limit window then deny, failed
   fetch keeps the last good set, concurrency-safe.
4. **`(*Verifier).Verify(ctx, token, typ, body)`**: `jws.Parse` + exact
   `typ`, Ed25519 signature against the JWKS key, required claims from
   `wire.TokenKindTable`, `iss`, `aud` (string or single-element array equal
   to self — multi-element or other always denies), `exp` and `iat` with 60 s
   skew, purpose rules per kind, `body_sha256` (base64url SHA-256,
   constant-time) on delivery/event. Unknown claims ignored;
   `user_ref`/`payment_id` optional. `ks-party+jwt` denies with
   `ErrUnsupportedKind` (party-signed, not verifiable against gateway JWKS).
   Sentinel errors usable with `errors.Is`.
5. **`verify.Middleware(v, typ, opts...)`**: `Authorization: Bearer`; body
   read once via `http.MaxBytesReader` (1 MiB default, option); a present
   webhook-id header must equal the `webhook_id` claim; dedupe after
   verification. Verification failure → 401, replay → 200 empty body, both
   without calling the handler; the handler gets a byte-exact body buffer and
   `ClaimsFromContext`; a ≥500 response or panic releases the reservation
   (panic re-raised).
6. **`(*Verifier).Ticket(ctx, token, typ, wantScope)`**: only
   `ks-approval+jwt`/`ks-access+jwt`; the six Recipient Verification Rules;
   exact scope match; `jti` consumed last (scope `jti`, until `exp`+60 s);
   repeated `jti` → `ErrReplay` (callers map to 409).
7. **Identity**: phone normalizes to E.164 digits without `+` (10–15 digits,
   no leading `0`, e.g. `6281234567890`, matching the backend
   `utils/phone.go`); pepper is exactly 32 raw bytes; shared vectors are
   authored here in `identity/testdata/vectors.json` with a fixed test pepper
   (the backend mirrors them later — authoring-time reconciliation).
8. **Envelope**: `Seal` injects the ephemeral X25519 key; `Open` rejects via
   the caller's `Decrypter`; `SelectEncKey` goes through `internal/jwk`
   `EncByKid`. The RFC 8037 A.6 vector is a **new** test in this phase (this
   task file previously claimed it already existed — corrected below).

## Checklist

### `SDK-VERIFY-001` — JWKS cache: kid-only selection, one bounded refetch

- [x] **Behavior**: TTL-cached gateway JWKS; keys selected only by the
  token's own header `kid`; at most one rate-limited refetch per unknown
  `kid` inside the window, then fail closed.
- **Accept**: a token under any JWKS key verifies against a cache hit;
  during a rotation (current + previous key in the JWKS) the previous
  key's token still verifies with no refetch.
- **Deny**: an unknown `kid` triggers exactly one refetch in the window;
  the next unknown-`kid` token denies — no second refetch, no key from
  any source but the JWKS.
- **Proving tests**: `TestJWKSCacheKidOnlySelection`,
  `TestJWKSCacheTTLExpiry`, `TestJWKSCacheOneRateLimitedRefetchThenDeny`
  (counting fake JWKS server), `TestJWKSCacheRotationAcceptsPreviousKey`.

### `SDK-VERIFY-002` — per-kind checks for all six kinds

- [x] **Behavior**: exact `typ`, `iss`, `aud`, `exp` (60 s skew),
  `body_sha256` over the exact POST bytes on delivery/event tokens, and
  required `purpose`/`webhook_id`/`jti` claims per Token Kinds row.
  `ks-event+jwt` accepts exactly four purposes — `settlement-notification`,
  `service-result`, `payment-required`, `service-receipt`. Unknown claim
  names are ignored (SDK-WIRE-004); an unknown `purpose` value denies.
- **Accept**: a correctly built token per kind verifies, including one
  `ks-event+jwt` per purpose and a delivery token carrying conditional
  `user_ref`/`payment_id` (SDK-WIRE-002: conditional, not required).
- **Deny**: wrong/missing `typ`, wrong `purpose`, missing required claim,
  foreign `iss`/`aud`, expired `exp`, and a mutated body (`body_sha256`
  mismatch) each deny — fail closed, no partial accept.
- **Proving tests**: `TestPerKindChecksAcceptValidTokens`,
  `TestPerKindChecksDenyMatrix`, `TestEventPurposeFourAcceptedOthersDeny`.

### `SDK-VERIFY-003` — callback middleware

- [x] **Behavior**: `verify.Middleware` wraps `http.Handler`, buffers the
  raw body exactly once, dedupes `webhook_id` (or `jti`) through
  `ReplayCache`, hands the handler verified claims + original bytes.
- **Accept**: one buffered read; the handler receives the verified claims
  and the byte-exact body.
- **Deny**: a replayed `webhook_id` never reaches the handler; a failed
  verification never reaches the handler.
- **Proving tests**: `TestMiddlewareBuffersBodyOnce`,
  `TestMiddlewareReplayNeverReachesHandler`.

### `SDK-VERIFY-004` — the six Recipient Verification Rules verbatim

- [x] **Behavior**: (1) signature against gateway JWKS, key by header
  `kid`, one refetch then deny; (2) exact `typ` per operation
  (`ks-approval+jwt` handoff, `ks-access+jwt` payment ticket); (3)
  `aud` = self and `iss` = gateway; (4) `exp` within 60 s skew; (5)
  `scope` matches the operation (`referral` / `export:<study>` /
  `listing:<id>`); (6) `jti` consumed once.
- **Accept**: a well-formed ticket for this recipient passes all six in
  any order.
- **Deny**: any single violated rule denies — each rule gets its own
  violation case, including a scope mismatch and a repeated `jti`.
- **Proving tests**: `TestRecipientRulesAllSixAccept`,
  `TestRecipientRuleScopeMismatchDenies`,
  `TestRecipientRuleJTIOnceOnlyDenies`,
  `TestRecipientRuleWrongTypAndAudDeny`.

### `SDK-VERIFY-C01` — deny matrix + rotation acceptance

- [x] **Behavior**: the composite acceptance criterion of §9.3.
- **Accept**: a post-rotation token verifies once the JWKS (current +
  previous) is loaded.
- **Deny**: expired, replayed, foreign-aud, wrong-typ, and body-mutated
  tokens each deny.
- **Proving tests**: `TestVerifyC01DenyMatrix`,
  `TestVerifyC01PostRotationAccepts`.

### `SDK-ID-001` — normalization + `hashfmt` HMAC hashes

- [x] **Behavior**: email lowercase + trim, phone E.164,
  `HMAC-SHA256(normalized, pepper)` as standard base64 of exactly 32
  bytes, or the `N/A` marker for a non-applicable field (gateway ADR-005).
- **Accept**: fixture inputs hash to the expected base64 (fixed test
  pepper) or `N/A`.
- **Deny**: a field that is neither applicable nor valid takes the
  documented marker path — never a truncated/garbage hash on the wire.
- **Proving tests**: `TestIdentityHashfmtVectors`,
  `TestIdentityNAMarkerForNonApplicableFields`.

### `SDK-ID-002` — format validation mirrors the gateway reject rule

- [x] **Behavior**: validate a hash as marker **or** standard base64 of
  exactly 32 bytes.
- **Accept**: the marker and well-formed 32-byte base64 validate.
- **Deny**: wrong length, bad base64, or raw bytes reject before any
  wire use.
- **Proving tests**: `TestHashFormatValidationAcceptsMarkerAndBase64`,
  `TestHashFormatValidationRejectsMalformed`.

### `SDK-ID-C01` — shared fixture vectors

- [x] **Behavior**: the shared input → expected-hash vectors pass with a
  fixed pepper (same vectors the backend adapter uses).
- **Accept**: every fixture row matches byte for byte.
- **Deny**: a single altered input/expectation fails the vector test.
- **Proving test**: `TestIdentitySharedFixtureVectors`.

### `SDK-ENV-001` — `Seal` per the normative JWE Envelope

- [x] **Behavior**: compact JWE with `alg: ECDH-ES`, `enc: A256GCM`,
  fresh ephemeral X25519 `epk` per message, protected-header `kid`,
  empty encrypted-key segment, Concat KDF (SHA-256, `AlgorithmID =
  "A256GCM"`, empty `apu`/`apv`, `keydatalen = 256`), AAD = encoded
  protected header.
- **Accept**: header/segments match the contract shape; two seals of the
  same payload differ (fresh `epk`) yet both open.
- **Deny**: a KDF/header deviation from the contract is a test failure,
  not a runtime fallback.
- **Proving tests**: `TestSealContractHeaderAndSegments`,
  `TestSealFreshEphemeralPerMessage`.

### `SDK-ENV-002` — recipient `use:enc` discovery

- [x] **Behavior**: discover the recipient's `use:enc` key from
  `GET /v1/parties/{id}/jwks`, select by JWE header `kid`.
- **Accept**: the recipient's published `use:enc` key seals a payload the
  recipient can open.
- **Deny**: unknown `kid` or missing `use:enc` fails closed — no
  ciphertext leaves the SDK.
- **Proving tests**: `TestSealRecipientEncKeyDiscovery`,
  `TestSealUnknownEncKidFailsClosed`.

### `SDK-ENV-003` — `Open` through the caller's `Decrypter`

- [x] **Behavior**: open with the caller's X25519 private key; reject
  malformed envelope / wrong `alg`/`enc` / auth failure before any
  plaintext is used; plaintext lives in the returned buffer only.
- **Accept**: a sealed payload opens to the original bytes.
- **Deny**: tampered ciphertext, wrong `alg`/`enc`, and malformed
  segments each reject with no plaintext returned.
- **Proving tests**: `TestOpenRejectsMalformedEnvelope`,
  `TestOpenRejectsTamperedCiphertext`.

### `SDK-ENV-C01` — RFC vector + round trip + tamper

- [x] **Behavior**: the composite acceptance criterion of §9.5.
- **Accept**: RFC 8037 A.6 vector passes; seal→open round trip is byte-
  identical.
- **Deny**: a tampered ciphertext/tag fails.
- **Proving tests**: `TestRFC8037A6Vector`,
  `TestSealOpenRoundTripByteIdentical`,
  `TestSealOpenTamperFails`.

## Files to create/edit

Create:

- `verify/errors.go`, `verify/options.go`, `verify/replay.go`,
  `verify/jwks_cache.go`, `verify/claims.go`, `verify/checks.go`,
  `verify/middleware.go`, `verify/rules.go` plus the tests
  (`replay_test.go`, `jwks_cache_test.go`, `checks_test.go`,
  `middleware_test.go`, `rules_test.go`, `helpers_test.go`,
  `verify_test.go`)
- `identity/normalize.go`, `identity/hash.go`, `identity/identity_test.go`
  (+ `identity/testdata/vectors.json` shared fixture vectors)
- `envelope/kdf.go`, `envelope/seal.go`, `envelope/open.go`,
  `envelope/jwks.go`, `envelope/envelope_test.go`, `envelope/jwks_test.go`,
  `envelope/fuzz_test.go`

Edit (only if the package contract changes):

- `verify/doc.go`, `identity/doc.go`, `envelope/doc.go` and their
  `README.md` file lists, plus the phase-2 doc alignment (`docs/ADR/005`,
  `docs/ARCHITECTURE.md` import table, `PROPOSAL.md` §7/§8/SDK-ID-001)

## Definition of Done

- [x] Every checklist item's proving tests green; accept and deny
      expectations both asserted (deny = fail closed, never partial).
- [x] SDK-VERIFY-C01 deny matrix green; rotation acceptance green.
- [x] SDK-ID-C01 shared fixture vectors green offline.
- [x] SDK-ENV-C01 green: RFC 8037 A.6 passes, round trip byte-identical,
      tampered ciphertext/tag fails.
- [x] Envelope fuzz target registered and smoke-run, no crashes.
- [x] `go test -race ./...` green with zero network and no test reading
      outside the module; `mise run qc` green.
- [x] Every new exported symbol has a doc comment; files ≤ 300 lines;
      complexity ≤ 15.

## Open items — closed

- **SDK-ID-C01 shared fixture vectors**: authored here in
  `identity/testdata/vectors.json` (email rows, phone rows, `N/A` marker
  cases) with the fixed test pepper pinned by the file; the backend adapter
  mirrors these vectors later. Authoring-time reconciliation only — no test
  reads another repo.
- **Pepper custody**: supplied by callers only — `HashEmail`/`HashPhone`
  require exactly 32 raw bytes and never generate, store, or log a pepper;
  the fixed test pepper lives in `identity/testdata/vectors.json` (mirrored
  by the inline test constant) and no production pepper is ever committed.

## Flagged upstream (gateway-side, not edited here)

- Gateway ADR-005's phone wording says "E.164" without clarifying that the
  `+` is dropped; SDK-ID-001 pins "E.164 digits, no '+'" (matching the
  backend `utils/phone.go`). Clarify the gateway ADR wording upstream — a
  gateway repo doc change, out of scope for this module.
