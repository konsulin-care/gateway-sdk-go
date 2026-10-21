# internal/jws

**Purpose**: compact JWS encode/verify on the standard library only
(RFC 7515 / RFC 7518): `alg` checks against the expected algorithm, Ed25519
and ES256 signature paths, and ES256 DER<->raw R||S conversion. Hand-written;
no `go-jose`, no `lestrrat-go/jwx` (ADR-002).

**Allowed imports** (PRD §7 dependency rules): standard library only. Never
re-exported; only `auth`, `verify`, and `gatewaytest` may use it.

**Related requirements**: SDK-AUTH-001, SDK-AUTH-C01, SDK-VERIFY-001.

**Planned files**:
- `jws.go` — compact serialization sign/verify, protected-header byte control
- `alg.go` — algorithm allow-list and per-alg checks
- `es256.go` — DER<->raw R||S conversion
- `jws_test.go` — RFC 7515 A.3 vectors
- `fuzz_test.go` — fuzz target on parsing

**Built by**: `docs/tasks/01-foundation-test-kit.md`.
