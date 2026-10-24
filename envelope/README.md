# envelope

**Purpose**: compact JWE seal/open per the gateway's normative JWE Envelope —
`alg: ECDH-ES`, `enc: A256GCM` over X25519, fresh ephemeral `epk` per message,
protected-header `kid`, empty encrypted-key segment, Concat KDF (SHA-256,
`AlgorithmID = "A256GCM"`, empty `apu`/`apv`, `keydatalen = 256`), AAD = encoded
protected header. Recipient `use:enc` key discovered from the party JWKS,
selected by header `kid`, unknown `kid` fails closed.

**Allowed imports** (PRD §7 dependency rules): standard library
(`crypto/ecdh`, `crypto/aes`, ...), `wire`, and `internal/jwk` for recipient
`use:enc` key selection only — never `internal/jws`; no jwk type is
re-exported.

**Related requirements**: SDK-ENV-001, SDK-ENV-002, SDK-ENV-003, SDK-ENV-C01.

**Files**:
- `doc.go` — package doc (allowed imports, requirement IDs)
- `kdf.go` — Concat KDF (SHA-256, `AlgorithmID = "A256GCM"`, empty `apu`/`apv`, `keydatalen = 256`)
- `seal.go` — `Seal` (ephemeral X25519 epk, AAD = protected header)
- `open.go` — `Open` through the caller's `Decrypter`; reject before any plaintext use
- `jwks.go` — `SelectEncKey` recipient `use:enc` discovery via `internal/jwk` `EncByKid`
- `envelope_test.go` — RFC 8037 A.6 vector, round trip byte-identical, tamper deny
- `jwks_test.go` — `SelectEncKey` discovery and fail-closed cases
- `fuzz_test.go` — `FuzzOpen` target

**Built by**: `docs/tasks/02-inbound-trust.md`.
