# Phase 1 — Foundation & Test Kit

## Objective

Build the crypto and contract foundation the rest of the SDK stands on:
`wire` typ/purpose/capability constants plus `*wire.Error` and the error
catalog, the hand-written stdlib JWS/JWK layers (`internal/jws`,
`internal/jwk`), `auth` (ks-party signing, enrollment proof of possession,
fresh `jti`), the golden-vector mirror script, and `gatewaytest` v1 so every
later phase has an offline test kit. Exit: **SDK-AUTH-C01 byte-exact green**.

## Depends on

- M0 bootstrap complete: `go.mod`, package skeleton (`doc.go` + `README.md`
  per package), `.mise.toml`, `.golangci.yml`, `scripts/qc.sh`, lefthook
  hooks, CI `pr-check.yml`, `testdata/golden/README.md`.
- Read-only access to the gateway repo (mirroring source, PRD §11).

## Requirement IDs

- `SDK-WIRE-002` — six `typ` constants, token purposes, capability catalog,
  token-kind table.
- `SDK-WIRE-003` — `*wire.Error{Code, Message, RequestID, Status}` and the
  known error catalog (`capability_denied`, `idempotency_in_progress`,
  `GW-PARTY-007`, …) for `errors.Is/As`.
- `SDK-AUTH-001` — `ks-party+jwt` signing with **Ed25519 default** (JWS
  header `alg` `EdDSA`): header `alg`/`kid` (RFC 7638 thumbprint),
  `iss`/`aud`/`iat`/`exp ≤ iat+300s`, single-use `jti`, exact `typ`.
  ES256 (ECDSA P-256) is an opt-in party-key algorithm only, reachable
  solely through an explicit opt-in key type — never the default.
- `SDK-AUTH-002` — enrollment proof of possession: `body_sha256`
  (base64url, no padding) over the exact POST bytes, proof in
  `Authorization`, body carries `enrollment_token`, `public_key`, `kid`,
  optional `alg`/`enc_public_key`. Body `alg` is the stored key algorithm
  (`Ed25519` or `ES256`, empty defaults to `Ed25519`); the JWT header
  `alg` is the JWS algorithm (`EdDSA` for Ed25519, `ES256` for P-256) and
  must match the stored key-row algorithm.
- `SDK-AUTH-003` — fresh `jti` per attempt; retries never replay a `jti`.
- `SDK-AUTH-C01` — byte-exact `ks-party` reproduction from
  `testdata/golden/ks-party.json` + `testonly-party-private.key`.
- `SDK-TEST-001` (v1 part) — `gatewaytest` fixture loader, fake JWKS
  server, token minter with a generated test key, deterministic
  `ReplayCache`; zero network.

(`SDK-WIRE-001` route DTOs are **not** phase 1 — they land with the routes
in `03-client-and-routes.md`.)

## Files to create/edit

Create:

- `wire/constants.go`, `wire/errors.go`, `wire/constants_test.go`,
  `wire/errors_test.go`
- `internal/jws/jws.go`, `internal/jws/alg.go`, `internal/jws/es256.go`,
  `internal/jws/jws_test.go`, `internal/jws/fuzz_test.go`
- `internal/jwk/jwk.go`, `internal/jwk/jwks.go`, `internal/jwk/thumbprint.go`,
  `internal/jwk/jwk_test.go`, `internal/jwk/fuzz_test.go`
- `auth/claims.go`, `auth/sign.go`, `auth/pop.go`, `auth/auth_test.go`
- `scripts/mirror-golden.sh` — copies the PRD §11 mirrored set verbatim
  from the gateway checkout into `testdata/golden/` (never the gateway
  signing key)
- `testdata/golden/gateway-jwks.json`, `ks-access.json`, `ks-approval.json`,
  `ks-delivery.json`, `ks-event-service-result.json`, `ks-party.json`,
  `ks-result.json`, `settlement-expired-buyer.json`,
  `settlement-expired-provider.json`, `settlement-paid-buyer.json`,
  `settlement-paid-provider.json`, `testonly-party-private.key` (script
  output, read-only)
- `gatewaytest/fixtures.go`, `gatewaytest/server.go`,
  `gatewaytest/minter.go`, `gatewaytest/replay.go`,
  `gatewaytest/gatewaytest_test.go`

Edit (only if a phase-1 symbol changes the package contract):

- `wire/doc.go`, `internal/jws/doc.go`, `internal/jwk/doc.go`,
  `auth/doc.go`, `gatewaytest/doc.go` and their `README.md` planned-file
  lists

## Direction (TDD)

1. **wire constants** — failing test first: assert the six `typ` strings,
   the five purposes, and the capability catalog match PRD §9.7 exactly;
   then add `wire/constants.go`.
2. **wire errors** — failing test for `*wire.Error` fields, envelope
   decoding of `{error: {code, message, request_id}}`, and `errors.Is/As`
   against catalog sentinels; then add `wire/errors.go`.
3. **mirror** — write `scripts/mirror-golden.sh`, run it once against the
   gateway checkout; failing test that every PRD §11 file loads and that
   `testonly-gateway-signing-private.key` is absent.
4. **internal/jwk** — failing RFC 7638 §3.1 thumbprint vector test and a
   JWKS parse test over `gateway-jwks.json` (current + previous key);
   implement; add the fuzz target on parsing.
5. **internal/jws** — failing RFC 8037 §3 Ed25519 JWS vector test (the
   default algorithm) plus alg allow-list checks (exact `typ`/`alg` per
   Token Kinds row, EdDSA only for gateway-signed kinds); then the ES256
   (opt-in party key, never default) RFC 7515 A.3 vector test with
   DER<->raw R||S conversion; implement with byte-exact protected-header
   control; add the fuzz target.
6. **auth** — failing SDK-AUTH-C01 test: sign the fixture claims at the
   fixture's fixed `iat`/`exp` with `testonly-party-private.key` and
   compare the produced `jwt` byte for byte; then claims/sign/pop.
7. **gatewaytest v1** — failing tests for the fixture loader, `httptest`
   JWKS server, token minter (generated Ed25519 test key), and the
   deterministic `ReplayCache` (same key → same verdict, no wall clock).
8. Run `go test -race ./...` and `mise run qc` after every step.

## Definition of Done

- [ ] `scripts/mirror-golden.sh` exists; running it yields all 12 PRD §11
      mirrored files under `testdata/golden/`, byte-identical to the
      gateway originals (`diff` clean), gateway signing key absent.
- [ ] SDK-AUTH-C01 green: byte-exact `ks-party` reproduction, and the same
      verification path accepts the produced token.
- [ ] SDK-AUTH-001/002/003 tests green (fresh `jti` per attempt proven by
      signing the same claims twice).
- [ ] RFC 8037 §3 (Ed25519 JWS, the default), RFC 7515 A.3 (ES256), and
      RFC 7638 §3.1 (thumbprint) vectors pass.
- [ ] ES256 is opt-in only: default signing and minting paths are EdDSA;
      no ES256 path is reachable without an explicit opt-in key type.
- [ ] Fuzz targets registered and smoke-run for the JWS and JWKS parsers
      (`go test -fuzz` briefly, no crashes).
- [ ] SDK-WIRE-002/003 tests green (constants match PRD §9.7, error
      catalog handles `errors.Is/As`).
- [ ] `gatewaytest` v1 usable: fixtures load, fake JWKS serves, minter
      produces verify-able tokens, ReplayCache deterministic.
- [ ] `go test -race ./...` green with zero network; `mise run qc` green.
- [ ] Every new exported symbol has a doc comment; files ≤ 300 lines;
      complexity ≤ 15.

## Open items

- Confirm the gateway checkout path/branch the mirror script reads
  (default `../gateway`) and whether the script should pin a gateway tag
  or commit for reproducible mirrors.
- Confirm where `testdata/golden/testonly-party-private.key` regeneration
  happens gateway-side (it must never be regenerated here).
