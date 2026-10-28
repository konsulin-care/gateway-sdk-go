# Changelog

Notable changes to this SDK. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semver v0.x (ADR-009) — minors may break, never silently: every break
carries an entry here and a [COMPATIBILITY.md](COMPATIBILITY.md) update in
the same PR.

## [Unreleased]

## [v0.1.0] - 2026-10-28

First release: the complete PRD (PROPOSAL.md) surface. Released under the
ADR-009 gate — green CI, green offline e2e, and green conformance against a
development-mode throwaway gateway (see [COMPATIBILITY.md](COMPATIBILITY.md)).
The `v0.1.0` tag is applied only to a `master` commit where CI — `quality`,
`e2e-offline`, and `e2e-gateway` conformance — is green; tagging is a manual
maintainer step, never automated (SDK-CONF-003).

### Added

- `client` — one `Client` with functional options (`WithBaseURL`,
  `WithSigner`, `WithHTTPClient`, `WithInsecureTransport`, `WithReplayCache`,
  `WithLogger`, `WithRetry`); idempotency keys stable across retries of one
  logical create; non-2xx responses surfaced as `*wire.Error` from the
  `{error: {code, message, request_id}}` envelope; zero-option construction
  fails (SDK-CLIENT-001…C01).
- `auth` — `ks-party+jwt` request signing, Ed25519 default and ES256 opt-in;
  RFC 7638 thumbprint kids; enrollment proof of possession with PoP
  `body_sha256` over the exact POST bytes; a fresh `jti` per attempt;
  byte-exact golden-vector reproduction (SDK-AUTH-001…C01).
- `wire` — DTOs for every contract body with byte-exact JSON tags, the six
  Token Kinds, purposes, capability names, the route table, and the `GW-*`
  error-code catalog with retry classification (ADR-011: new `Idempotency-Key`
  only after a terminal 402).
- `gateway`, `parties`, `identities`, `approvals`, `listings`, `payments`,
  `webhooks` — one typed method per §9.6 party-facing route; admin routes
  deliberately excluded (PRD §5).
- `verify` — gateway-JWKS verifier with TTL cache, kid-only key selection and
  one rate-limited refetch per unknown kid; per-kind checks for all six token
  kinds (exact `typ`, `iss`, `aud`, `exp` with 60 s skew, `body_sha256`);
  callback middleware with single-buffer reads and `webhook_id` dedupe; the
  six Recipient Verification Rules (`Ticket`); pluggable `ReplayCache` with
  an in-memory default (SDK-VERIFY-001…C01).
- `identity` — email/phone normalization and gateway `hashfmt`
  `HMAC-SHA256` hashes with the `N/A` marker, format validation, and the
  shared fixture vectors the backend adapter mirrors (SDK-ID-001…C01).
- `envelope` — compact JWE `Seal`/`Open` (`ECDH-ES` + `A256GCM` over X25519,
  fresh ephemeral per message, SP 800-56A Concat KDF) with recipient
  `use:enc` key discovery and RFC-pinned key-agreement vectors
  (SDK-ENV-001…C01).
- `gatewaytest` — the offline test kit: golden-vector loaders with
  `MANIFEST.json` verification (ADR-004), fake JWKS and gateway servers,
  a token minter, a deterministic `ReplayCache`, canned handlers for every
  §9.6 route with idempotency and scripted-sequence support, and opt-in
  admin fakes (SDK-TEST-001).
- `internal/integration` — offline end-to-end flows (enroll → signed calls →
  approval → direct exchange → callback) proven zero-network by
  construction, plus the README-recipe mirror test (SDK-TEST-002,
  SDK-README-001).
- `internal/adminboot`, `internal/conformance`, `cmd/conformance` — the
  conformance runner: QC-chain positive flows, the SDK-CONF-002 negative
  cases, exit codes 0/1/2 with the failing case named, and a build-info
  version (SDK-CONF-001…003, SDK-CONF-C01). The runner shipped in this
  release reports version `v0.1.0`, versioned with the module and matching
  this SDK tag (SDK-CONF-003).
- `testdata/golden` — contract vectors mirrored from the gateway with a
  hash manifest; `mise run qc --mirror-check` is the local drift check
  (ADR-004).
- Repo — ADRs 001–012, phase task files, tested README recipes,
  CONTRIBUTING/SECURITY/CHANGELOG/COMPATIBILITY, and a CI DCO check.

[Unreleased]: https://github.com/konsulin-care/gateway-sdk-go/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/konsulin-care/gateway-sdk-go/releases/tag/v0.1.0
