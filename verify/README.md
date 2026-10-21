# verify

**Purpose**: the inbound trust layer — gateway JWKS cache with TTL and one
rate-limited refetch per unknown `kid` (then fail closed), per-kind token
checks for all six token kinds, the six Recipient Verification Rules verbatim,
callback middleware wrapping `http.Handler` with `webhook_id`/`jti` dedupe
through `ReplayCache`, and the `ReplayCache` interface with an in-memory
default.

**Allowed imports** (PRD §7 dependency rules): standard library, `internal/jws`,
`internal/jwk`, `wire`.

**Related requirements**: SDK-VERIFY-001, SDK-VERIFY-002, SDK-VERIFY-003,
SDK-VERIFY-004, SDK-VERIFY-C01.

**Planned files**:
- `jwks_cache.go` — TTL cache, bounded refetch window, rotation (current + previous key)
- `checks.go` — exact `typ`, `iss`, `aud`, `exp` (60 s skew), `body_sha256`, per-kind claims
- `middleware.go` — `http.Handler` wrapper, raw body buffered exactly once
- `rules.go` — the six Recipient Verification Rules
- `replay.go` — `ReplayCache` interface + in-memory default
- `verify_test.go` — SDK-VERIFY-C01 deny matrix, rotation acceptance

**Built by**: `docs/tasks/02-inbound-trust.md`.
