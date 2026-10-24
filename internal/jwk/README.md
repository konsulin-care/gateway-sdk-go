# internal/jwk

**Purpose**: JWK and JWKS parsing (RFC 7517) and RFC 7638 thumbprints on the
standard library only. Thumbprints define party key `kid`s (never a configured
value); JWKS parsing backs both outbound signing key lookup and inbound
verification key selection. Signing keys (OKP/Ed25519, EC/P-256) resolve via
`SigByKid`; JWE recipient keys (OKP/X25519, only `use:enc` with `alg` absent
or `ECDH-ES`) resolve via `EncByKid`; an empty `kid` matches nothing.

**Allowed imports** (PRD §7 dependency rules): standard library only. Never
re-exported; only `auth`, `verify`, `gatewaytest`, and `envelope`
(recipient `use:enc` key selection) may use it.

**Related requirements**: SDK-AUTH-C01, SDK-VERIFY-001, SDK-ENV-002.

**Files**:
- `doc.go` — package doc (allowed imports, requirement IDs)
- `jwk.go` — single JWK parse (kty/crv/alg/use/kid validation: Ed25519, P-256, X25519 `use:enc`)
- `jwks.go` — JWKS parse (current + previous key during rotation) with `SigByKid`/`EncByKid` kid-only selection
- `thumbprint.go` — RFC 7638 thumbprint (SHA-256, required-members order)
- `jwk_test.go` — RFC 7638 §3.1 vector, `testdata/golden/gateway-jwks.json`, sig/enc selector split
- `fuzz_test.go` — fuzz target on parsing

**Built by**: `docs/tasks/01-foundation-test-kit.md` (v1), extended in
`docs/tasks/02-inbound-trust.md` (X25519 `use:enc`, `SigByKid`/`EncByKid`).
