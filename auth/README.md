# auth

**Purpose**: outbound party request signing — `ks-party+jwt` claims per the
gateway Token Kinds row, header `kid` = RFC 7638 thumbprint of the public key,
a fresh `jti` per attempt, and the enrollment proof of possession
(`body_sha256` over the exact POST bytes, proof in `Authorization`).

**Allowed imports** (PRD §7 dependency rules): standard library, `internal/jws`,
`internal/jwk`, `wire`.

**Related requirements**: SDK-AUTH-001, SDK-AUTH-002, SDK-AUTH-003,
SDK-AUTH-C01.

**Key parsing** (`keys.go`): `ParseEd25519PrivateKey` accepts gateway
`cmd/genkey` output — standard (padded) base64 wrapping either a 32-byte
seed (expanded with `ed25519.NewKeyFromSeed`) or an already-expanded
64-byte private key; trailing line breaks from the generator output are
tolerated. Malformed base64 or any other decoded length is rejected
(fail closed, ADR-015). Parse errors carry only format and length facts
— never the input string and never decoded key material.

**Planned files**:
- `claims.go` — `ks-party+jwt` claim construction (`iss`, `aud`, `iat`, `exp ≤ iat+300s`, `jti`, `typ`)
- `sign.go` — signing with the caller's `crypto.Signer`, `kid` from the thumbprint
- `pop.go` — enrollment proof of possession (`body_sha256`, base64url no padding)
- `keys.go` — `ParseEd25519PrivateKey` (ADR-015): genkey-format input
  parsing; errors omit the input string and key material
- `auth_test.go` — byte-exact SDK-AUTH-C01 against `testdata/golden/ks-party.json`
- `keys_test.go` — golden `kid`, seed form, and error-omits-input coverage

**Built by**: `docs/tasks/01-foundation-test-kit.md`.
