# Phase 2 — Inbound Trust

## Objective

Make the SDK trustworthy on the inbound side: `verify` (JWKS cache with
bounded refetch, per-kind checks, callback middleware, the six Recipient
Verification Rules, `ReplayCache`), `identity` (normalization + gateway
`hashfmt` HMAC hashes), and `envelope` (compact JWE seal/open over X25519).
Exit: **SDK-VERIFY-C01, SDK-ID-C01, SDK-ENV-C01 green offline**.

## Depends on

- `docs/tasks/01-foundation-test-kit.md` (internal/jws, internal/jwk,
  `wire` constants/error catalog, `gatewaytest` minter + deterministic
  ReplayCache for fixtures).

## Requirement IDs

- `SDK-VERIFY-001` — JWKS TTL cache, key selection by header `kid` only,
  at most one rate-limited refetch per unknown `kid`, then fail closed;
  rotation (current + previous key) keeps verifying.
- `SDK-VERIFY-002` — per-kind checks for all six kinds: exact `typ`,
  `iss`, `aud`, `exp` (60 s skew), `body_sha256` over the exact POST bytes
  on delivery/event tokens, required `purpose`/`webhook_id`/`jti` claims.
- `SDK-VERIFY-003` — callback middleware wrapping `http.Handler`,
  `webhook_id` (or `jti`) dedupe through `ReplayCache`, raw body buffered
  exactly once.
- `SDK-VERIFY-004` — the six Recipient Verification Rules verbatim
  (signature/kid, exact `typ`, `aud` = self + `iss` = `gateway`, `exp`
  within 60 s skew, `scope` match, single-use `jti`).
- `SDK-VERIFY-C01` — deny matrix: expired / replayed / foreign-aud /
  wrong-typ / body-mutated each deny; post-rotation token verifies once
  the JWKS (current + previous) is loaded.
- `SDK-ID-001` — email lowercase+trim, phone E.164,
  `HMAC-SHA256(normalized, pepper)` as standard base64 of exactly 32 bytes,
  or the `N/A` marker (gateway `hashfmt`, ADR-005).
- `SDK-ID-002` — format validation mirroring the gateway reject rule
  (marker or valid 32-byte base64).
- `SDK-ID-C01` — shared fixture vectors (inputs → expected hashes for a
  fixed pepper) pass.
- `SDK-ENV-001` — `Seal`: `alg: ECDH-ES`, `enc: A256GCM`, fresh X25519
  `epk` per message, protected-header `kid`, empty encrypted-key segment,
  Concat KDF (SHA-256, `AlgorithmID = "A256GCM"`, empty `apu`/`apv`,
  `keydatalen = 256`), AAD = encoded protected header.
- `SDK-ENV-002` — recipient `use:enc` key from
  `GET /v1/parties/{id}/jwks`, selected by JWE header `kid`; unknown `kid`
  or missing `use:enc` fails closed.
- `SDK-ENV-003` — `Open` through the caller's `Decrypter`; malformed
  envelope / wrong `alg`/`enc` / auth failure rejected before any
  plaintext is used; plaintext never logged or persisted.
- `SDK-ENV-C01` — RFC 8037 A.6 vector passes; seal→open round trip
  byte-identical; tampered ciphertext/tag fails.

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

## Direction (TDD)

1. **ReplayCache first** — failing test for the `verify` interface +
   in-memory default: atomic lookup-and-insert per key, `jti` and
   `webhook_id` scopes, concurrent use under `-race`; then `replay.go`.
2. **JWKS cache** — failing tests: TTL expiry, `kid`-only selection,
   exactly one refetch per unknown `kid` inside the rate-limit window and
   deny after it, rotation acceptance (current + previous key); then
   `jwks_cache.go` on top of `internal/jwk`.
3. **Per-kind checks** — failing deny-matrix test first (expired,
   replayed, foreign-aud, wrong/missing `typ`, mutated body ⇒
   `body_sha256` mismatch, missing `purpose`/`webhook_id`/`jti`); then
   `checks.go`.
4. **Middleware** — failing test that the raw body is buffered exactly
   once, the handler receives verified claims + original bytes, and a
   replayed `webhook_id` never reaches the handler; then
   `middleware.go`.
5. **Six rules** — failing test per rule (scope `referral` /
   `export:<study>` / `listing:<id>`, single-use `jti`); then `rules.go`.
6. **identity** — failing fixture-vector test (fixed pepper → expected
   hashes, `N/A` marker, malformed-hash reject); then `normalize.go` +
   `hash.go` with constant-time compares.
7. **envelope** — failing RFC 8037 A.6 vector test, then round-trip and
   tamper tests; implement `seal.go`/`open.go` on `crypto/ecdh` +
   `crypto/aes`; add the parsing fuzz target.
8. Run `go test -race ./...` and `mise run qc` after every step.

## Definition of Done

- [ ] SDK-VERIFY-001..004 tests green; one-refetch-then-deny proven with
      a counting fake JWKS server.
- [ ] SDK-VERIFY-C01 deny matrix green; rotation acceptance green
      (previous key still verifies, unknown `kid` after one refetch
      denies).
- [ ] SDK-ID-C01 shared fixture vectors green offline; SDK-ID-002 reject
      rule mirrors the gateway.
- [ ] SDK-ENV-C01 green: RFC 8037 A.6 passes, round trip byte-identical,
      tampered ciphertext/tag fails.
- [ ] Envelope fuzz target registered and smoke-run, no crashes.
- [ ] `go test -race ./...` green with zero network; `mise run qc` green.
- [ ] Every new exported symbol has a doc comment; files ≤ 300 lines;
      complexity ≤ 15.

## Open items

- SDK-ID-C01 needs the *shared* fixture vectors the backend adapter tests
  use — confirm their source (gateway/backend repo) or author them here
  and have the backend mirror them.
- Confirm the pepper is supplied by callers only (test pepper lives in
  fixtures; no pepper ever committed outside `testdata`).
