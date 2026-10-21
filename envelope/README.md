# envelope

**Purpose**: compact JWE seal/open per the gateway's normative JWE Envelope —
`alg: ECDH-ES`, `enc: A256GCM` over X25519, fresh ephemeral `epk` per message,
protected-header `kid`, empty encrypted-key segment, Concat KDF (SHA-256,
`AlgorithmID = "A256GCM"`, empty `apu`/`apv`, `keydatalen = 256`), AAD = encoded
protected header. Recipient `use:enc` key discovered from the party JWKS,
selected by header `kid`, unknown `kid` fails closed.

**Allowed imports** (PRD §7 dependency rules): standard library
(`crypto/ecdh`, `crypto/aes`, ...), `wire`.

**Related requirements**: SDK-ENV-001, SDK-ENV-002, SDK-ENV-003, SDK-ENV-C01.

**Planned files**:
- `seal.go` — `Seal` (ephemeral X25519 epk, Concat KDF, AAD = protected header)
- `open.go` — `Open` through the caller's `Decrypter`; reject before any plaintext use
- `envelope_test.go` — RFC 8037 A.6 vector, round trip byte-identical, tamper deny
- `fuzz_test.go` — fuzz target on parsing

**Built by**: `docs/tasks/02-inbound-trust.md`.
