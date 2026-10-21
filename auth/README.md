# auth

**Purpose**: outbound party request signing — `ks-party+jwt` claims per the
gateway Token Kinds row, header `kid` = RFC 7638 thumbprint of the public key,
a fresh `jti` per attempt, and the enrollment proof of possession
(`body_sha256` over the exact POST bytes, proof in `Authorization`).

**Allowed imports** (PRD §7 dependency rules): standard library, `internal/jws`,
`internal/jwk`, `wire`.

**Related requirements**: SDK-AUTH-001, SDK-AUTH-002, SDK-AUTH-003,
SDK-AUTH-C01.

**Planned files**:
- `claims.go` — `ks-party+jwt` claim construction (`iss`, `aud`, `iat`, `exp ≤ iat+300s`, `jti`, `typ`)
- `sign.go` — signing with the caller's `crypto.Signer`, `kid` from the thumbprint
- `pop.go` — enrollment proof of possession (`body_sha256`, base64url no padding)
- `auth_test.go` — byte-exact SDK-AUTH-C01 against `testdata/golden/ks-party.json`

**Built by**: `docs/tasks/01-foundation-test-kit.md`.
