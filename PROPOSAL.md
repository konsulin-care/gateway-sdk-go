# PRD — Gateway SDK for Go (public module)

## 1. Metadata & conventions

- **Module**: `github.com/konsulin-care/gateway-sdk-go` — its own repository, its own `go.mod`, its own semver tags; published as a public Go module (no registry — `proxy.golang.org` picks up the tags).
- **License**: MIT (`LICENSE` in this repo) so both the closed-source gateway-adjacent tooling and the AGPL backend may depend on it.
- **Go**: 1.26. **Runtime dependencies: stdlib only** — JWS (Ed25519/ES256), JWKS, JWE `ECDH-ES` + `A256GCM` over X25519, SP 800-56A Concat KDF, HMAC — all from `crypto/*`. No `golang-jwt`, no `go-jose`, no `golang.org/x/crypto`, no other `require` entries.
- **Contract authority** (order, conflicts resolve upward): (1) the gateway's Bruno collections at `../gateway/docs/api/` plus the normative sections of the gateway's `docs/api/AGENTS.md` — *Token Kinds*, *Recipient Verification Rules*, *JWE Envelope*, *Gateway Key Rotation*; (2) the mirrored golden vectors in `testdata/golden/`; (3) this PRD. This PRD never redefines wire format.
- **Requirement notation**: IDs `SDK-*`, priority `M`/`S`/`C`, SHALL/SHOULD/MAY, terse acceptance criteria.
- **Independence rule (binding)**: written fresh from the contract. Nothing is copied from the AGPL backend or from the gateway's reference implementations (`capture_verify.go`, `minter.go`, `jwe.go`). The shared artifact between gateway and SDK is the **contract, not code**.
- **The gateway does not import this module**, and this module never imports the gateway. The backend consumes it as an external module pinned to a semver tag behind one adapter package.

## 2. Executive summary

The SDK is the single Go client and verifier for everything the gateway offers a party: enrollment and key rotation, identity registration/resolution/linking, approval tickets, listings, payments, webhook enqueue/sync/status/result — plus the inbound side (verifying gateway-signed callbacks and direct-channel tickets), federation identity hashing, and the JWE envelope. Stdlib-only and MIT, so any party can `go get` it and the gateway QC can pin its conformance runner.

## 3. Background & problem

The backend originally grew an in-repo gateway client. That couples the wire contract to one repo's release cadence, puts the client under AGPL (no MIT carve-out possible inside that repo), and leaves conformance as a backend concern. A separate public module fixes all three: independent semver, clean licensing, a first-class home for golden vectors and `cmd/conformance`. The gateway still must not import it — shared **contract, not shared code**.

## 4. Goals & objectives

| Goal | Target |
|---|---|
| Typed client for every party route | Every party-facing route in `../gateway/docs/api/` has a typed method — the §9 SDK-API table is the checklist |
| Golden vectors verify | Every mirrored vector passes the SDK verifier; `ks-party` reproduced **byte for byte** from `testonly-party-private.key` (SDK-AUTH-C01) |
| Conformance | `cmd/conformance` passes against a live gateway; gateway `qc --flow` runs the pinned runner after v0.1.0 |
| `gatewaytest` offline | Unit tests run with zero network (httptest + fixtures only) |
| Zero third-party runtime deps | `go.mod` carries no `require` beyond the module itself |

## 5. Non-goals (v1 — binding)

- No admin routes in the public client (operator surface stays gateway-side; `cmd/conformance` carries its own minimal admin bootstrap for setup only).
- No server-side logic: no queues, no persistence, no daemon state beyond caches.
- No consumer-stack dependencies (no Redis/Postgres/frameworks); `ReplayCache` is an interface with an in-memory default.
- No codegen/OpenAPI toolchain — wire types are hand-written from the contract.
- No streaming export envelopes in v1 (§15).
- No key custody: keys stay with the caller; the SDK never generates, stores, or rotates production keys for callers.

## 6. Personas & user stories

- **Party Go developer** — "One `go get`, typed calls for every route, and my gateway callbacks verified by wrapping my handler."
- **Party operator** — "Enroll and rotate keys from the CLIs this SDK powers; paste env values, done."
- **Gateway QC (CI)** — "Pin the conformance runner by version; contract drift fails `qc --flow`."
- **SDK maintainer** — "Contract change → golden vectors → conformance green → tag; semver tells consumers what moved."

## 7. Architecture & flows

Package layout (one directory per concern; files ≤ 300 lines):

```
gateway-sdk-go/
  client/           # Client core: options, transport, idempotency, retry, errors
  auth/             # ks-party signing: claims, kid, proof of possession
  internal/jose/    # JWS compact encode/verify, JWK/JWKS, RFC 7638 thumbprints
  verify/           # inbound verification: JWKS cache, per-kind checks, middleware
  identity/         # normalization + HMAC identity hashes (gateway ADR-005)
  envelope/         # compact JWE seal/open (ECDH-ES + A256GCM over X25519)
  parties/ identities/ approvals/ listings/ payments/ webhooks/   # typed routes
  wire/             # DTOs, typ constants, purposes, capability names, *wire.Error
  gatewaytest/      # fixture loaders, fakes, httptest helpers (offline)
  cmd/conformance/  # conformance runner against a live gateway
  testdata/golden/  # mirrored vectors incl. testonly-party-private.key
```

Dependency rules (normative): `wire` and `internal/jose` import stdlib only; `internal/jose` is never re-exported; `auth` = `internal/jose` + `wire`; route packages = `client` + `auth` + `wire`; `verify` = `internal/jose` + `wire` + the `ReplayCache` interface; `envelope` = `crypto/ecdh` + `crypto/aes` + `wire`; nothing outside `internal/jose` implements JWS/JWK primitives; `gatewaytest` and `cmd/conformance` may import public packages, nothing imports `gatewaytest` except tests and the conformance command; no import cycles.

Key flows (normative for development):

- **Enrollment with proof of possession**: generate an Ed25519 keypair; `kid` = RFC 7638 thumbprint of the public key (never a configured value); optionally generate an X25519 keypair and publish the public half as `enc_public_key` (base64 raw 32 bytes) so counterparties can seal envelopes to this party via its `use:enc` JWKS entry. Body: `{enrollment_token, public_key, kid, alg, enc_public_key?}` to `POST /v1/parties/{id}/enroll`. The proof is a `ks-party+jwt` signed by the **new** key with `body_sha256` over the exact POST bytes, travelling in `Authorization: Bearer` — never in the body (it would hash itself). The gateway verifies against the submitted key.
- **Signed request**: every party-authenticated call signs a fresh `ks-party+jwt` (SDK-AUTH claims), with a **fresh `jti` per attempt** — a retry never replays a `jti`. `Idempotency-Key` on every create, stable across the retries of one logical create.
- **Inbound verification middleware**: `verify.Middleware` wraps an `http.Handler`; it buffers the raw body once, verifies gateway-signed tokens (`ks-delivery+jwt`, `ks-event+jwt`, …) against the cached gateway JWKS with the key selected by the token's own header `kid`, exact `typ`, `aud`, `exp` (60 s skew), `body_sha256` over the exact bytes, and `webhook_id` dedupe via `ReplayCache`; success hands the handler verified claims plus the original body.
- **Direct exchange**: `approvals.Mint` gets a ticket from the gateway; the recipient runs the six Recipient Verification Rules (`verify.Ticket`), then payload flows party-to-party with `envelope.Seal` to the recipient's `use:enc` key discovered from the recipient's party JWKS. The gateway never sees payload bytes.

## 8. Security model

- **Key custody**: callers pass a `crypto.Signer` (Ed25519 or ECDSA-P256 for ES256) into `client`/`auth`; the SDK never serializes, persists, or logs private keys. Encryption opens through a `Decrypter` interface implemented by the caller's X25519 key; same custody rule.
- **Fail closed**: any signature, `typ`, claim, audience, expiry, `body_sha256`, or envelope failure denies — never a partial accept, never a "verify best effort" mode.
- **Exact `typ`**: string equality per Token Kinds row (`ks-party+jwt`, `ks-approval+jwt`, `ks-access+jwt`, `ks-delivery+jwt`, `ks-event+jwt`, `ks-result+jwt`); a missing or generic `typ` fails even under a valid signature (RFC 8725 §3.11).
- **Key selection**: only the token's own header `kid`; keys come only from JWKS; an unknown `kid` triggers **one** rate-limited JWKS refetch (bounded per window, no refetch storms), then fail closed.
- **Rotation**: the gateway JWKS serves current plus previous key during a rotation (each `kid` its RFC 7638 thumbprint); the SDK selects by `kid`, so no config change is ever needed to accept a rotated key.
- **Replay**: `ReplayCache` is an interface (`jti`/`webhook_id` scope) with an in-memory default; callers plug Redis etc. for multi-instance. Dedupe lookup and insert are atomic per key.
- **Transport**: `https` only — base URLs and JWKS fetches reject `http` unless the caller opts into `WithInsecureTransport` (local dev/test; fails at construction in production builds).
- **Logging**: `log/slog` hooks log method, path, status, request_id, `kid`, `typ` — never bodies, tokens, keys, or the pepper.
- **Constant-time compares**: `hmac.Equal`/`subtle.ConstantTimeCompare` for `body_sha256`, identity hashes, and any secret-derived byte compare.
- **Threat model**: (1) network attacker — TLS + fail-closed verification; (2) replay of callbacks/tickets — `ReplayCache` + single-use `jti`; (3) typ/claim downgrade — exact per-kind checks; (4) key substitution — JWKS-only keys, header-`kid` selection, one bounded refetch; (5) hostile counterparty endpoint — payload is JWE-sealed to the recipient before it leaves; (6) log leakage — §8 logging rule; (7) supply chain — stdlib-only runtime deps make the dependency graph auditable in one page.

## 9. Functional requirements

### 9.1 Client core `SDK-CLIENT`

- `SDK-CLIENT-001 (M)` — SHALL expose one `Client` built with functional options: `WithBaseURL`, `WithSigner`, `WithHTTPClient`, `WithInsecureTransport`, `WithReplayCache`, `WithLogger`, `WithRetry`; every method takes `context.Context`.
- `SDK-CLIENT-002 (M)` — SHALL generate an `Idempotency-Key` for every create when the caller does not supply one, and keep it stable across retries of that call.
- `SDK-CLIENT-003 (M)` — SHALL surface every non-2xx as `*wire.Error` parsed from the error envelope `{error: {code, message, request_id}}`, preserving `code` and `request_id`.
- `SDK-CLIENT-C01`: a `Client` with zero options fails at construction (no silent defaults to production URLs).

### 9.2 Auth `SDK-AUTH`

- `SDK-AUTH-001 (M)` — SHALL sign outbound party requests with `ks-party+jwt` exactly per the Token Kinds row: header `alg` matching the signer, header `kid` = RFC 7638 thumbprint of the public key, `iss` = party_id, `aud` = gateway, `iat` ≤ now + 60 s, `exp − iat` ≤ 300 s, single-use `jti`, exact `typ` `ks-party+jwt`. The gateway resolves the party key from the header `kid` alone; the SDK must never send an extra key-selection hint.
- `SDK-AUTH-002 (M)` — SHALL build enrollment proof of possession: proof signed by the submitted key with `body_sha256` (base64url, no padding) over the exact POST bytes, proof in the `Authorization` header, body carries `enrollment_token`, `public_key`, `kid`, optional `alg` and `enc_public_key`.
- `SDK-AUTH-003 (M)` — SHALL mint a **fresh `jti` per attempt**; a retried request never carries a previous attempt's `jti`.
- `SDK-AUTH-C01` — byte-exact vector: signing `testdata/golden/ks-party.json`'s claims with `testdata/golden/testonly-party-private.key` at the fixture's fixed `iat`/`exp` reproduces the committed `jwt` string byte for byte; the same verification path accepts it.

### 9.3 Inbound verification `SDK-VERIFY`

- `SDK-VERIFY-001 (M)` — SHALL cache the gateway JWKS with TTL, select keys only by the token's header `kid`, refetch at most once per unknown `kid` inside a rate-limit window, then fail closed; during a rotation the previous key (listed in the JWKS) keeps verifying.
- `SDK-VERIFY-002 (M)` — SHALL enforce per-kind checks for all six kinds: exact `typ`, `iss`, `aud`, `exp` (60 s skew), `body_sha256` over the exact POST bytes on delivery/event tokens, and required `purpose`/`webhook_id`/`jti` claims per kind.
- `SDK-VERIFY-003 (M)` — SHALL ship callback middleware wrapping `http.Handler` with `webhook_id` (or `jti`) dedupe through `ReplayCache`, buffering the raw body exactly once.
- `SDK-VERIFY-004 (M)` — SHALL implement the six Recipient Verification Rules verbatim: (1) signature against gateway JWKS, key by header `kid`, one refetch then deny; (2) exact `typ` per operation; (3) `aud` = self and `iss` = `gateway`; (4) `exp` within 60 s skew; (5) `scope` matches the operation (`referral` / `export:<study>` / `listing:<id>`); (6) `jti` consumed once.
- `SDK-VERIFY-C01`: expired/replayed/foreign-aud/wrong-typ/body-mutated tokens each deny; a token signed after a rotation verifies once the JWKS (current + previous) is loaded.

### 9.4 Identity `SDK-ID`

- `SDK-ID-001 (M)` — SHALL normalize (email: lowercase + trim; phone: E.164) and compute `HMAC-SHA256(normalized, pepper)` rendered as standard base64 of exactly 32 bytes, or the `N/A` marker when a field is not applicable — the gateway `hashfmt` convention (ADR-005).
- `SDK-ID-002 (M)` — SHALL expose format validation mirroring the gateway's reject rule (marker or valid 32-byte base64), so malformed hashes never reach the wire.
- `SDK-ID-C01`: shared test vectors (fixture inputs → expected hashes for fixed pepper) pass — same vectors the backend adapter tests use.

### 9.5 Envelope `SDK-ENV`

- `SDK-ENV-001 (M)` — SHALL `Seal` payloads as compact JWE per the gateway's normative JWE Envelope: `alg: ECDH-ES`, `enc: A256GCM`, fresh ephemeral X25519 `epk` per message, protected-header `kid`, empty encrypted-key segment, Concat KDF (SHA-256, `AlgorithmID = "A256GCM"`, empty `apu`/`apv`, `keydatalen = 256`), AAD = encoded protected header.
- `SDK-ENV-002 (M)` — SHALL discover the recipient's `use:enc` key from `GET /v1/parties/{id}/jwks`, selected by the JWE header `kid`; unknown `kid` or missing `use:enc` fails closed (no payload leaves unprotected).
- `SDK-ENV-003 (M)` — SHALL `Open` envelopes through the caller's `Decrypter` (X25519 private key); malformed envelope, wrong `alg`/`enc`, or auth failure is rejected before any plaintext is used. Plaintext lives in the returned buffer only — never logged, never persisted by the SDK.
- `SDK-ENV-C01`: the RFC 8037 A.6 X25519 key-agreement vector passes; a sealed-then-opened round trip is byte-identical; a tampered ciphertext/tag fails.

### 9.6 API surface `SDK-API`

Every party-facing route, one typed method (admin routes excluded per §5):

| Package | Method | Route | Capability | Idempotency-Key |
|---|---|---|---|---|
| `parties` | `Enroll` | `POST /v1/parties/{id}/enroll` | public (token + PoP) | required |
| `parties` | `Rotate` | `POST /v1/parties/{id}/keys` | party auth (any valid key) | required |
| `parties` | `JWKS` | `GET /v1/parties/{id}/jwks` | public | — |
| `parties` | `Health` | `GET /v1/parties/{id}/health` | party auth | — |
| `identities` | `Register` | `POST /v1/identities/register` | `identity:register` | required |
| `identities` | `Resolve` | `POST /v1/identities/resolve` | `identity:resolve` | — (read, not a create) |
| `identities` | `Link` | `POST /v1/identities/link` | `identity:link` | required |
| `approvals` | `Mint` | `POST /v1/approvals` | `approval:referral` / `approval:export:<study>` | required |
| `listings` | `Create` | `POST /v1/listings` | `listing:enlist` | required |
| `listings` | `List` | `GET /v1/listings` | public | — |
| `payments` | `Create` | `POST /v1/payments` | `payment:create` | required |
| `payments` | `Get` | `GET /v1/payments/{id}` | party auth | — |
| `payments` | `AccessToken` | `POST /v1/payments/{id}/access-token` | party auth | required |
| `webhooks` | `Enqueue` | `POST /v1/webhooks` | `webhook:invoke` | required |
| `webhooks` | `Sync` | `POST /v1/webhooks/sync` | `webhook:invoke` | required |
| `webhooks` | `Status` | `GET /v1/webhooks/{id}/status` | party auth | — |
| `webhooks` | `Result` | `POST /v1/webhooks/{id}/result` | public (single-use result ticket) | required |
| `gateway` | `JWKS` | `GET /.well-known/jwks` | public | — |
| `gateway` | `Health` | `GET /health` | public | — |

- Inbound gateway→party surfaces are **not** client rows: payment callback (`POST /v1/payments/callback`), settlement notification, service-result delivery, and webhook delivery/result callbacks arrive at the party's own endpoints and are covered by `SDK-VERIFY` middleware.
- Coverage rule (normative): the table is the complete outbound party-call surface — every party-facing request in `../gateway/docs/api/` tagged `auth:party`, `auth:public`, or `auth:ticket` appears exactly once (the webhook result callback carries `auth:ticket`; it is in the table as `webhooks.Result`). Exclusions are explicit, never path-prefix based: (a) the `admin` folder per §5 — including `POST /v1/admin/auth/login`, which is tagged `auth:public` but is the operator session surface; (b) any `auth:admin` route wherever it is registered, **including `GET /v1/webhooks/dlq`** (operator DLQ view, outside the `/v1/admin` prefix); (c) the `auth:provider` reference contracts (payment callback, settlement notification, service-result delivery), which are inbound to the party and covered by `SDK-VERIFY` middleware; and (d) the admin bootstrap trio used by `cmd/conformance` setup (§9.10).
- `SDK-API-001 (M)` — every row SHALL exist with request/response structs in `wire`, context support, and typed errors; the table is the coverage checklist for M3 exit.
- `SDK-API-002 (M)` — SHALL encode `Idempotency-Key` on the rows marked required and reject 4xx without retry (§9.8).

### 9.7 Wire types `SDK-WIRE`

- `SDK-WIRE-001 (M)` — SHALL define DTOs for every request/response body in the contract; JSON tags match the Bruno examples byte-for-byte in field names.
- `SDK-WIRE-002 (M)` — SHALL export the six `typ` constants, token purposes (`webhook-delivery`, `settlement-notification`, `service-result`, `webhook-result`, `admin-auth`), the capability catalog (`approval:referral`, `approval:export:<study>`, `listing:enlist`, `webhook:invoke`, `payment:create`, `identity:register`, `identity:resolve`, `identity:link`, `accept:referral`, `accept:export:<study>`), and the token-kind table.
- `SDK-WIRE-003 (M)` — SHALL export `*wire.Error{Code, Message, RequestID, Status}` as the one error type surfaced by every call, plus the known error catalog (incl. `capability_denied`, `idempotency_in_progress`, `GW-PARTY-007`) for programmatic `errors.Is/As` handling.

### 9.8 Retry `SDK-RETRY`

- `SDK-RETRY-001 (M)` — SHALL sign **fresh** on every attempt (new `jti`, new `iat`); the `Idempotency-Key` stays constant across attempts of one logical create.
- `SDK-RETRY-002 (M)` — retryable: network errors (dial/timeout/reset), `409 idempotency_in_progress`, `429`, `502`, `503`, `504` — bounded exponential backoff with jitter, honoring `Retry-After`.
- `SDK-RETRY-003 (M)` — terminal (never retried): `400`, `401`, `402`, `403` (incl. `capability_denied` — a missing grant must surface, never be retried around), `404`, `413`, `422`.
- `SDK-RETRY-C01`: a 409→200 sequence replays with the same `Idempotency-Key` and a different `jti`; a 403 is returned on the first response.

### 9.9 Test kit `SDK-TEST`

- `SDK-TEST-001 (M)` — `gatewaytest` SHALL load `testdata/golden` fixtures, build fake gateway servers (`httptest`), mint fake inbound tokens for middleware tests, and provide a deterministic `ReplayCache`; tests run with zero network.
- `SDK-TEST-002 (M)` — the backend adapter and each integration point SHALL be testable against `gatewaytest` offline (mirrors of the gateway behaviors the backend touches).

### 9.10 Conformance `SDK-CONF`

- `SDK-CONF-001 (M)` — `cmd/conformance` SHALL run against a **live gateway** end to end, bootstrapping through the admin API (`POST /v1/admin/auth/login` → `POST /v1/admin/parties` → `POST /v1/admin/parties/{id}/enrollment-token`) in its own code, then exercising enrollment, rotation, JWKS, identities, approvals, listings, payments, webhooks, and result callback — the QC-chain party surface.
- `SDK-CONF-002 (M)` — SHALL include negative cases: wrong signing key, replayed enrollment token, wrong/missing `typ`, `body_sha256` mismatch, expired token, unknown `kid` after one refetch, revoked party, missing capability (`capability_denied`), idempotency replay (byte-identical response).
- `SDK-CONF-003 (M)` — SHALL be versioned (`v0.x` tags like the module) and pinned by the gateway: `qc --flow` runs the pinned runner version once v0.1.0 exists (a gateway-side task).
- `SDK-CONF-C01`: one command exits non-zero on any contract mismatch with the failing case named.

### 9.11 README recipes `SDK-README`

- `SDK-README-001 (M)` — README SHALL carry runnable recipes for: enrollment, signed calls, callback middleware, direct exchange, and **fetching the federation pepper** — enqueue/sync-invoke the `federation-pepper` listing through the gateway, keep the returned sealed JWE as received, then `envelope.Open` it at startup with the party's X25519 `Decrypter` into memory only (never write plaintext pepper to disk or env).

## 10. Non-functional requirements

- **Correctness**: golden vectors + conformance are the release gates; `-race` clean; fuzz targets on JWS/JWKS/JWE parsing and error-envelope decoding.
- **Performance**: sign/verify adds < 1 ms p95 per call excluding network; JWKS cache hit adds no I/O; retry backoff never blocks a `context.Context` cancellation.
- **Footprint**: zero third-party runtime deps; module adds no global state, no goroutines unless the caller starts them.
- **Thread safety**: `Client`, JWKS cache, and `ReplayCache` default are safe for concurrent use.
- **Hygiene**: no bodies/tokens/keys/pepper in logs or errors; errors carry `request_id`, never secrets.
- **Compatibility**: semver v0.x with a documented break policy (§12) and `COMPATIBILITY.md` (§11).

## 11. Golden vectors & compatibility

- **Mirrored set** (gateway → `testdata/golden/`, verbatim): `gateway-jwks.json`; `ks-access.json`, `ks-approval.json`, `ks-delivery.json`, `ks-event-service-result.json`, `ks-party.json`, `ks-result.json`; `settlement-expired-buyer.json`, `settlement-expired-provider.json`, `settlement-paid-buyer.json`, `settlement-paid-provider.json`; and `testonly-party-private.key` — the party key so the SDK can prove byte-exact `ks-party` signing (SDK-AUTH-C01). The gateway's `testdata/golden/README.md` is instructions, not a vector — it stays gateway-side.
- **Never mirrored**: `testonly-gateway-signing-private.key` stays in the gateway repo only; the SDK verifies with public JWKS.
- **Read-only mirror**: vectors are verbatim copies — this repo never edits them locally; regeneration happens only at the gateway and flows here by mirroring.
- **Regeneration**: regenerate at the gateway, mirror the full set here, SDK ships a new tag; either side drifting turns one CI red (lockstep).
- **`COMPATIBILITY.md`**: table of gateway version ↔ SDK version ↔ conformance-runner version, updated in the same PR as any contract-affecting change; consumers pin SDK tags and consult this table before upgrading.

## 12. Development guide

- **TDD**: write the failing test first for every `SDK-*` behavior; `github.com/stretchr/testify` — `require` for setup, `assert` for outcomes.
- **Style**: files ≤ 300 lines (split packages, not truncation); doc comment on every exported symbol (purpose, parameters, return value); `interface`-style small interfaces over fat types; `const` declarations over mutable vars; no `interface{}`/`any` in exported signatures — explicit types, explicit error handling, no blank imports.
- **Commits**: conventional (`feat:`, `fix:`, `refactor:`, `docs:`, `chore:`), subject < 75 chars, DCO `Signed-off-by` on every commit.
- **CI** (required checks): `gofmt` check, `go vet`, `golangci-lint`, `govulncheck`, `go test -race ./...`, fuzz smoke on crypto parsers, golden-vector tests.
- **Release**: semver **v0.x** — minors may break with a CHANGELOG entry and a `COMPATIBILITY.md` update; no tag without green CI + conformance.
- **Repo files**: `LICENSE` (MIT), `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `COMPATIBILITY.md` — all present before v0.1.0.

## 13. Milestones (with entry/exit gates)

- **M0 — bootstrap**: repo, `go.mod` (Go 1.26, zero deps), MIT `LICENSE`, CI (§12), doc scaffolding. *Exit: CI green on an empty package.*
- **M1 — JWS + auth**: `internal/jose`, JWKS, RFC 7638 thumbprints, `auth`, `wire` typ/claims; golden vectors mirrored. *Exit: SDK-AUTH-C01 byte-exact `ks-party` green.*
- **M2 — verify + identity**: `verify` (JWKS cache, per-kind checks, middleware, six rules), `identity` vectors. *Exit: SDK-VERIFY + SDK-ID green offline.*
- **M3 — envelope + API surface**: `envelope` (RFC 8037 A.6), every §9.6 row, `SDK-RETRY`, `gatewaytest`. *Exit: SDK-API checklist complete, race-clean.*
- **M4 — conformance + v0.1.0**: `cmd/conformance` (positive + negative), README recipes incl. federation pepper, `COMPATIBILITY.md`, CHANGELOG. *Exit: conformance green against a live gateway → tag **v0.1.0**.*
- **M5 — adoption**: backend pins v0.1.0 behind its adapter; gateway `qc --flow` runs the pinned conformance runner (gateway-side task, after v0.1.0). *Exit: QC chain + conformance green in gateway CI.*

## 14. Risks & mitigations

- **Contract drift** → golden-vector lockstep + pinned conformance in gateway QC; `COMPATIBILITY.md` on every contract change.
- **Hand-rolled crypto (no go-jose)** → stdlib primitives only (`crypto/ecdh`, `crypto/aes`, `crypto/hmac`, `crypto/ed25519`), RFC test vectors (incl. 8037 A.6), fuzzing, external review before v0.1.0.
- **JWKS unavailability / refetch storms** → TTL cache + one rate-limited refetch per unknown `kid`, then fail closed.
- **Gateway↔SDK version skew** → pinning by tag, `COMPATIBILITY.md`, conformance runner pinned alongside.
- **v0.x instability for consumers** → CHANGELOG + compatibility table per break; no silent wire changes.
- **Caller key-custody mistakes** → `crypto.Signer`/`Decrypter` interfaces (keys never accepted as bytes in options), doc'd threat model, no key logging by construction.

## 15. Open decisions

- **Streaming export envelopes in v1**: chunked AEAD for research exports — deferred (§5); revisit post-v0.1.0 with real workload data.
- **Gateway importing `wire`**: could dedupe type drift with the backend adapter, but breaks the shared-contract-not-code rule — decision deferred to the gateway side.
- **ES256 envelope**: ECDH-ES over P-256 recipients — not required by the current contract (JWE Envelope mandates X25519 `use:enc`); revisit only if a contract amendment adds it.
