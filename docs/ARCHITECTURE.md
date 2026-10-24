# Architecture — Gateway SDK for Go

Normative for this repository. Conflicts resolve upward through the contract
authority chain in `AGENTS.md`: gateway contract (Bruno collections + normative
gateway sections) → mirrored golden vectors → `PROPOSAL.md`. This file mirrors
`PROPOSAL.md` §7 (post-M0 layout) and never redefines wire format.

## 1. Package layout

Go library layout: public packages at the module root, no `pkg/`; non-public
code under `internal/`. Files ≤ 300 lines everywhere.

```
gateway-sdk-go/
  wire/                 # DTOs, typ constants, purposes, capabilities, *wire.Error
  internal/jws/         # compact JWS encode/verify (RFC 7515/7518), alg checks,
                        #   ES256 DER<->raw R||S — hand-written, no go-jose/jwx
  internal/jwk/         # JWK/JWKS parse (RFC 7517), RFC 7638 thumbprints —
                        #   signing keys + X25519 use:enc recipient keys
  auth/                 # ks-party signing: claims, kid, proof of possession, fresh jti
  client/               # Client core: options, transport, idempotency, retry, errors
  verify/               # inbound trust: JWKS cache, per-kind checks, middleware, ReplayCache
  identity/             # normalization + HMAC identity hashes (gateway ADR-005)
  envelope/             # compact JWE seal/open (ECDH-ES + A256GCM over X25519)
  gateway/              # public gateway routes: JWKS (/.well-known/jwks), Health (/health)
  parties/ identities/ approvals/ listings/ payments/ webhooks/   # typed routes
  gatewaytest/          # fixture loaders, fakes, httptest helpers (offline test kit)
  internal/adminboot/   # admin login/party/enrollment-token/capabilities bootstrap
                        #   for conformance setup — never public (PRD §5)
  internal/conformance/ # shared conformance cases (positive + negative)
  internal/integration/ # offline end-to-end tests against gatewaytest, no build tag
  cmd/conformance/      # thin main.go entry point; logic in internal/conformance
  testdata/golden/      # read-only mirror of gateway vectors (PRD §11)
```

## 2. Dependency rules and import table

Normative rules (PRD §7):

- Non-test code imports the standard library or this module only. The only
  third-party dependency is testify, test-only. Enforced by depguard and
  `qc --deps`.
- `wire`, `internal/jws`, `internal/jwk` import **stdlib only** — they are the
  leaves.
- `internal/jws` and `internal/jwk` are never re-exported; nothing outside them
  implements JWS/JWK primitives; only `auth`, `verify`, and `gatewaytest` use
  `internal/jws`, and those three plus `envelope` use `internal/jwk`
  (recipient `use:enc` key selection only).
- `envelope` uses `crypto/ecdh` + `crypto/aes` + `wire` + `internal/jwk`
  (recipient `use:enc` key selection, no jwk type re-exported) — JWE never
  passes through `internal/jws`.
- `gatewaytest` is imported only by test files (including the test-only
  `internal/integration` package) and the conformance runner
  (`internal/conformance` + `cmd/conformance`). No import cycles;
  `client` imports no route package.

| Package | May import (module) | Notes |
|---|---|---|
| `wire` | — | stdlib only; contract leaf |
| `internal/jws` | — | stdlib only; never re-exported |
| `internal/jwk` | — | stdlib only; never re-exported |
| `auth` | `wire`, `internal/jws`, `internal/jwk` | signs outbound party requests |
| `client` | `wire`, `auth` | imports no route packages |
| `verify` | `wire`, `internal/jws`, `internal/jwk` | defines the `ReplayCache` interface |
| `identity` | `wire` | `crypto/hmac` identity hashes |
| `envelope` | `wire`, `internal/jwk` | `crypto/ecdh`, `crypto/aes`; `internal/jwk` for `use:enc` recipient key selection |
| `gateway` | `client`, `auth`, `wire` | public gateway routes |
| `parties` | `client`, `auth`, `wire` | typed routes |
| `identities` | `client`, `auth`, `wire` | typed routes |
| `approvals` | `client`, `auth`, `wire` | typed routes |
| `listings` | `client`, `auth`, `wire` | typed routes |
| `payments` | `client`, `auth`, `wire` | typed routes |
| `webhooks` | `client`, `auth`, `wire` | outbound only; inbound via `verify` |
| `gatewaytest` | public packages, `internal/*` where a fake must mint real tokens (`internal/jws`, `internal/jwk`) | test kit (token minter, fake JWKS); imported only per rule above |
| `internal/adminboot` | `wire` | never part of the public client |
| `internal/conformance` | public packages, `gatewaytest`, `internal/adminboot` (setup only) | shared cases |
| `internal/integration` | public packages, `gatewaytest` | tests only, no build tag |
| `cmd/conformance` | `internal/conformance` | thin `main`; admin setup lives in `internal/conformance` |

## 3. Key flows (normative for development)

**Enrollment with proof of possession**: generate an **Ed25519** keypair —
Ed25519 (JWS `alg` `EdDSA`) is the default party-key algorithm; ES256 (ECDSA
P-256) is an opt-in fallback for party keys, never the default — and derive
`kid` = RFC 7638 thumbprint of the public key (never a configured value);
optionally generate an X25519 keypair and publish the public half as
`enc_public_key` (base64 raw 32 bytes) so counterparties can seal envelopes via
the party's `use:enc` JWKS entry. Body `{enrollment_token, public_key, kid,
alg, enc_public_key?}` → `POST /v1/parties/{id}/enroll`. The body `alg` is the
**stored key algorithm** — `Ed25519` or `ES256` — while the JWT header `alg` is
the **JWS algorithm** — `EdDSA` for an Ed25519 key, `ES256` for a P-256 key —
and the header `alg` must match the stored key-row algorithm (`EdDSA` ↔
`Ed25519`, `ES256` ↔ `ES256`). The proof is a `ks-party+jwt` signed by the
**new** key with `body_sha256` over the exact POST bytes, travelling in
`Authorization: Bearer` — never in the body (it would hash itself). The
gateway verifies against the submitted key.

**Signed request**: every party-authenticated call signs a fresh
`ks-party+jwt` (SDK-AUTH claims), with a **fresh `jti` per attempt** — a retry
never replays a `jti`. `Idempotency-Key` on every create, stable across the
retries of one logical create.

**Inbound verification middleware**: `verify.Middleware` wraps an
`http.Handler`; it buffers the raw body once, verifies gateway-signed tokens
(`ks-delivery+jwt`, `ks-event+jwt`, …) against the cached gateway JWKS with the
key selected by the token's own header `kid`, exact `typ`, `aud`, `exp` (60 s
skew), `body_sha256` over the exact bytes, and `webhook_id` dedupe via
`ReplayCache`; success hands the handler verified claims plus the original
body.

**Direct exchange**: `approvals.Mint` gets a ticket from the gateway; the
recipient runs the six Recipient Verification Rules (`verify.Ticket`), then
payload flows party-to-party with `envelope.Seal` to the recipient's `use:enc`
key discovered from the recipient's party JWKS. The gateway never sees payload
bytes.

## 4. Security model (summary)

- **Algorithms**: the SDK signs with **Ed25519 (JWS `alg` `EdDSA`) by
  default** and verifies gateway-signed tokens **EdDSA-only**. **ES256 (ECDSA
  P-256) is an opt-in party-key algorithm only** — reachable solely through an
  explicit opt-in key type, never a default signing or verification path. The
  JWT header `alg` must match the stored key-row algorithm (`EdDSA` ↔ `Ed25519`,
  `ES256` ↔ `ES256`); enrollment body `alg` carries the stored value (`Ed25519`
  or `ES256`), not the header value.
- **Key custody** stays with the caller: `crypto.Signer` / `Decrypter`
  interfaces; the SDK never generates, stores, rotates, serializes, or logs
  private keys.
- **Fail closed**: any signature, `typ`, claim, audience, expiry,
  `body_sha256`, or envelope failure denies — never a partial accept.
- **Exact `typ`** per Token Kinds row; missing/generic `typ` fails even under
  a valid signature (RFC 8725 §3.11).
- **Kid-only key selection** from JWKS only: one rate-limited refetch per
  unknown `kid`, then deny. Rotation serves current + previous key, each `kid`
  its RFC 7638 thumbprint, so no config change ever follows a rotation.
- **Replay**: `ReplayCache` interface (`jti`/`webhook_id`, atomic per key) with
  an in-memory default; single-use `jti`, `webhook_id` dedupe.
- **Transport**: `https` only unless the caller opts into
  `WithInsecureTransport` (local dev). **Logging**: method/path/status/
  request_id/`kid`/`typ` only — never bodies, tokens, keys, or the pepper.
  **Constant-time** compares for `body_sha256`, identity hashes, and secret
  bytes.
- Full threat model: `PROPOSAL.md` §8.

## 5. Golden-vector lockstep

- `testdata/golden/` is a **read-only, verbatim mirror** of the gateway's
  vectors (PRD §11): gateway JWKS, the six token fixtures, the four settlement
  fixtures, and `testonly-party-private.key` (so SDK-AUTH-C01 can prove
  byte-exact `ks-party` signing).
- The gateway signing key (`testonly-gateway-signing-private.key`) is **never
  mirrored** — the SDK verifies with public JWKS only.
- This repo never edits vectors locally; regeneration happens only at the
  gateway and flows here by mirroring (`scripts/mirror-golden.sh`, phase 1).
- Either side drifting turns one CI red (lockstep). Contract-affecting changes
  update `COMPATIBILITY.md` (gateway ↔ SDK ↔ conformance-runner) in the same
  PR; consumers pin SDK tags.

## 6. Testing strategy (layered)

1. **Unit, offline**: zero network — `httptest` + fixtures, `-race` clean,
   testify (`require` setup, `assert` outcomes), fuzz targets on JWS/JWKS/JWE
   parsing. Runs locally (`go test ./...`) and in the CI `quality` job.
2. **Offline e2e**: `internal/integration` drives the full flows (enroll →
   signed calls → approval → direct exchange → callback middleware) against
   `gatewaytest`, **no build tag** — `go test -race ./internal/integration/...`
   is required on every PR (`e2e-offline` job; fork PRs rely on quality +
   e2e-offline).
3. **Throwaway gateway e2e**: CI `e2e-gateway` job pulls the pinned **private
   ghcr** gateway image (same-repo PRs, pushes, nightly, dispatch — skipped
   for fork PRs, skipped counts as passing) and runs
   `mise run e2e-gateway --smoke`. Ephemeral config, fresh keys, never
   production. Extended with `cmd/conformance` in phase 4.
4. **Gateway-side conformance pin**: after v0.1.0, the gateway's
   `qc --flow` runs the pinned `cmd/conformance` version in gateway CI —
   M5 follow-up, gateway/backend work, not this repo.

## 7. Release gates

- `go build ./...`, `go vet ./...`, and `mise run qc` green (format, lint with
  complexity ≤ 15, vet, ≤ 300-line files, secrets, deps, `-race` tests, vuln).
- Golden vectors and RFC vectors green; fuzz targets seeded in CI.
- Offline e2e green on every PR; conformance green against the throwaway
  gateway before any tag.
- No tag without green CI + conformance. v0.x semver: minors may break with a
  CHANGELOG entry and a `COMPATIBILITY.md` update in the same PR.
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `COMPATIBILITY.md` present
  before v0.1.0.
