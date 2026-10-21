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

**Planned files**:
- `runner.go` — case execution, named failures, non-zero exit on mismatch
- `positive.go` — QC-chain happy paths
- `negative.go` — SDK-CONF-002 deny cases
- `conformance_test.go` — case registry tests

**Built by**: `docs/tasks/04-integration-and-release.md`.
