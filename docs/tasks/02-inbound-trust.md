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

## Checklist

### `SDK-VERIFY-001` — JWKS cache: kid-only selection, one bounded refetch

- [ ] **Behavior**: TTL-cached gateway JWKS; keys selected only by the
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

- [ ] **Behavior**: exact `typ`, `iss`, `aud`, `exp` (60 s skew),
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

- [ ] **Behavior**: `verify.Middleware` wraps `http.Handler`, buffers the
  raw body exactly once, dedupes `webhook_id` (or `jti`) through
  `ReplayCache`, hands the handler verified claims + original bytes.
- **Accept**: one buffered read; the handler receives the verified claims
  and the byte-exact body.
- **Deny**: a replayed `webhook_id` never reaches the handler; a failed
  verification never reaches the handler.
- **Proving tests**: `TestMiddlewareBuffersBodyOnce`,
  `TestMiddlewareReplayNeverReachesHandler`.

### `SDK-VERIFY-004` — the six Recipient Verification Rules verbatim

- [ ] **Behavior**: (1) signature against gateway JWKS, key by header
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

- [ ] **Behavior**: the composite acceptance criterion of §9.3.
- **Accept**: a post-rotation token verifies once the JWKS (current +
  previous) is loaded.
- **Deny**: expired, replayed, foreign-aud, wrong-typ, and body-mutated
  tokens each deny.
- **Proving tests**: `TestVerifyC01DenyMatrix`,
  `TestVerifyC01PostRotationAccepts`.

### `SDK-ID-001` — normalization + `hashfmt` HMAC hashes

- [ ] **Behavior**: email lowercase + trim, phone E.164,
  `HMAC-SHA256(normalized, pepper)` as standard base64 of exactly 32
  bytes, or the `N/A` marker for a non-applicable field (gateway ADR-005).
- **Accept**: fixture inputs hash to the expected base64 (fixed test
  pepper) or `N/A`.
- **Deny**: a field that is neither applicable nor valid takes the
  documented marker path — never a truncated/garbage hash on the wire.
- **Proving tests**: `TestIdentityHashfmtVectors`,
  `TestIdentityNAMarkerForNonApplicableFields`.

### `SDK-ID-002` — format validation mirrors the gateway reject rule

- [ ] **Behavior**: validate a hash as marker **or** standard base64 of
  exactly 32 bytes.
- **Accept**: the marker and well-formed 32-byte base64 validate.
- **Deny**: wrong length, bad base64, or raw bytes reject before any
  wire use.
- **Proving tests**: `TestHashFormatValidationAcceptsMarkerAndBase64`,
  `TestHashFormatValidationRejectsMalformed`.

### `SDK-ID-C01` — shared fixture vectors

- [ ] **Behavior**: the shared input → expected-hash vectors pass with a
  fixed pepper (same vectors the backend adapter uses).
- **Accept**: every fixture row matches byte for byte.
- **Deny**: a single altered input/expectation fails the vector test.
- **Proving test**: `TestIdentitySharedFixtureVectors`.

### `SDK-ENV-001` — `Seal` per the normative JWE Envelope

- [ ] **Behavior**: compact JWE with `alg: ECDH-ES`, `enc: A256GCM`,
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

- [ ] **Behavior**: discover the recipient's `use:enc` key from
  `GET /v1/parties/{id}/jwks`, select by JWE header `kid`.
- **Accept**: the recipient's published `use:enc` key seals a payload the
  recipient can open.
- **Deny**: unknown `kid` or missing `use:enc` fails closed — no
  ciphertext leaves the SDK.
- **Proving tests**: `TestSealRecipientEncKeyDiscovery`,
  `TestSealUnknownEncKidFailsClosed`.

### `SDK-ENV-003` — `Open` through the caller's `Decrypter`

- [ ] **Behavior**: open with the caller's X25519 private key; reject
  malformed envelope / wrong `alg`/`enc` / auth failure before any
  plaintext is used; plaintext lives in the returned buffer only.
- **Accept**: a sealed payload opens to the original bytes.
- **Deny**: tampered ciphertext, wrong `alg`/`enc`, and malformed
  segments each reject with no plaintext returned.
- **Proving tests**: `TestOpenRejectsMalformedEnvelope`,
  `TestOpenRejectsTamperedCiphertext`.

### `SDK-ENV-C01` — RFC vector + round trip + tamper

- [ ] **Behavior**: the composite acceptance criterion of §9.5.
- **Accept**: RFC 8037 A.6 vector passes; seal→open round trip is byte-
  identical.
- **Deny**: a tampered ciphertext/tag fails.
- **Proving tests**: `TestRFC8037A6Vector` (already green — keep green),
  `TestSealOpenRoundTripByteIdentical`,
  `TestSealOpenTamperFails`.

## Files to create/edit

Create:

- `verify/jwks_cache.go`, `verify/checks.go`, `verify/middleware.go`,
  `verify/rules.go`, `verify/replay.go`, `verify/verify_test.go`
- `identity/normalize.go`, `identity/hash.go`, `identity/identity_test.go`
  (+ `identity/testdata/` fixture vectors)
- `envelope/seal.go`, `envelope/open.go`, `envelope/envelope_test.go`,
  `envelope/fuzz_test.go`

Edit (only if the package contract changes):

- `verify/doc.go`, `identity/doc.go`, `envelope/doc.go` and their
  `README.md` planned-file lists

## Definition of Done

- [ ] Every checklist item's proving tests green; accept and deny
      expectations both asserted (deny = fail closed, never partial).
- [ ] SDK-VERIFY-C01 deny matrix green; rotation acceptance green.
- [ ] SDK-ID-C01 shared fixture vectors green offline.
- [ ] SDK-ENV-C01 green: RFC 8037 A.6 passes, round trip byte-identical,
      tampered ciphertext/tag fails.
- [ ] Envelope fuzz target registered and smoke-run, no crashes.
- [ ] `go test -race ./...` green with zero network and no test reading
      outside the module; `mise run qc` green.
- [ ] Every new exported symbol has a doc comment; files ≤ 300 lines;
      complexity ≤ 15.

## Open items

- SDK-ID-C01 shared fixture vectors: confirm the backend adapter's source
  vectors or author them here and have the backend mirror them (authoring-
  time reconciliation — no test reads another repo).
- Confirm the pepper is supplied by callers only (test pepper lives in
  fixtures; no pepper ever committed outside `testdata`).
