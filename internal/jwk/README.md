# internal/jwk

**Purpose**: JWK and JWKS parsing (RFC 7517) and RFC 7638 thumbprints on the
standard library only. Thumbprints define party key `kid`s (never a configured
value); JWKS parsing backs both outbound signing key lookup and inbound
verification key selection.

**Allowed imports** (PRD §7 dependency rules): standard library only. Never
re-exported; only `auth`, `verify`, and `gatewaytest` may use it.

**Related requirements**: SDK-AUTH-C01, SDK-VERIFY-001, SDK-ENV-002.

**Planned files**:
- `jwk.go` — single JWK parse (kty/crv/alg/use/kid validation)
- `jwks.go` — JWKS parse (current + previous key during rotation)
- `thumbprint.go` — RFC 7638 thumbprint (SHA-256, required-members order)
- `jwk_test.go` — RFC 7638 §3.1 vector, `testdata/golden/gateway-jwks.json`
- `fuzz_test.go` — fuzz target on parsing

**Built by**: `docs/tasks/01-foundation-test-kit.md`.
