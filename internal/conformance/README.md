# internal/conformance

**Purpose**: the shared conformance cases executed by `cmd/conformance` against
a live gateway — positive flows over the QC-chain party surface (enrollment,
rotation, JWKS, identities, approvals, listings, payments, webhooks, result
callback) plus the negative cases: wrong signing key, replayed enrollment
token, wrong/missing `typ`, `body_sha256` mismatch, expired token, unknown
`kid` after one refetch, revoked party, missing capability
(`capability_denied`), idempotency replay.

**Allowed imports** (PRD §7 dependency rules): standard library and public SDK
packages (plus `internal/adminboot` for setup).

**Related requirements**: SDK-CONF-001, SDK-CONF-002, SDK-CONF-003,
SDK-CONF-C01.

**Files**:
- `registry.go` — ordered case registry (Kind, Case, Env, `Registry()`)
- `positive.go` — QC-chain happy paths (SDK-CONF-001)
- `negative.go` — SDK-CONF-002 deny cases
- `callback.go` — plain-HTTP result-callback receiver
- `doc.go` — package doc plus the shared case helpers (client builders, probes)
- `conformance_test.go` — QC-chain registry and import tests
- `cases_test.go` — negative-case and callback-receiver tests

**Built by**: `docs/tasks/04-integration-and-release.md`.
