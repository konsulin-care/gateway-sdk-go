# envelope

**Purpose**: compact JWE seal/open per the gateway's normative JWE Envelope —
`alg: ECDH-ES`, `enc: A256GCM` over X25519, fresh ephemeral `epk` per message,
protected-header `kid`, empty encrypted-key segment, Concat KDF (SHA-256,
`AlgorithmID = "A256GCM"`, empty `apu`/`apv`, `keydatalen = 256`), AAD = encoded
protected header. Recipient `use:enc` key discovered from the party JWKS,
selected by header `kid`, unknown `kid` fails closed.

On top of the plain seal/open, the package serves the **Bound Envelope**
(SDKP-001): `SealBound` wraps the payload in the normative
`{v:1, from, to, service, iat, nonce, data}` wrapper before sealing, and
`OpenBound` re-opens it against `Expectations` with fail-closed wrapper
checks. `EncKeyResolver` (SDKP-002) caches recipient `use:enc` keys per
party, and `ParseX25519PrivateKey` / `EncJWK` (SDKP-006) handle gateway
key parsing and JWKS rendering.

**Bound envelope rules** — `OpenBound` never partially accepts; the first
failure returns nil data:

- **Window**: the wrapper `iat` must be no older than the effective
  `MaxAge` — `DefaultMaxAge` (5 min) when `Expectations.MaxAge` is zero,
  with `MaxMaxAge` (15 min) the largest a caller may request (negative or
  larger values fail closed) — and no more than 60 s in the future.
- **Nonce**: an empty `Binding.Nonce` is replaced by a fresh >=128-bit
  (16-byte) base64url value at seal time; at open, an empty nonce or one
  longer than 64 chars fails closed before any cache lookup, then the
  `(from, nonce)` pair is atomically reserved in the caller's
  `wire.ReplayCache` under `wire.ScopeNonce` until
  `now + max(10 min, MaxAge + 60 s)` — a replayed pair or any cache error
  denies.
- **Data cap**: wrapper `data` larger than 524288 bytes fails closed.

**Allowed imports** (PRD §7 dependency rules): standard library
(`crypto/ecdh`, `crypto/aes`, ...), `wire`, and `internal/jwk` for recipient
`use:enc` key selection only — never `internal/jws`; no jwk type is
re-exported.

**Related requirements**: SDK-ENV-001, SDK-ENV-002, SDK-ENV-003, SDK-ENV-C01;
SDKP-001 (bound envelope), SDKP-002 (enc-key resolver), SDKP-006 (key
parsing).

**Files**:
- `doc.go` — package doc (allowed imports, requirement IDs)
- `kdf.go` — Concat KDF (SHA-256, `AlgorithmID = "A256GCM"`, empty `apu`/`apv`, `keydatalen = 256`)
- `seal.go` — `Seal` (ephemeral X25519 epk, AAD = protected header)
- `open.go` — `Open` through the caller's `Decrypter`; reject before any plaintext use
- `jwks.go` — `SelectEncKey` recipient `use:enc` discovery via `internal/jwk` `EncByKid`
- `select.go` — `SelectRecipientEncKey` single-`use:enc`-key selection or deny
- `bound.go` — `Binding` and `SealBound` (SDKP-001 bound wrapper)
- `bound_open.go` — `OpenBound` (normative check order: decrypt, `v`,
  `to`, `from`, `service`, `iat` window, nonce replay, data cap)
- `expect.go` — `Expectations`, `ExpectationsFromClaims`,
  `DefaultMaxAge` (5 min), `MaxMaxAge` (15 min)
- `bound_fresh.go`, `bound_replay.go` — iat window and nonce format /
  replay-reservation rules (unexported)
- `resolver.go` — `FetchFunc`, `EncKeyResolver`, `NewEncKeyResolver`:
  TTL cache, `Refresh` rate-limited to one refetch per TTL window (SDKP-002)
- `keys.go` — `ParseX25519PrivateKey` (std base64, exactly 32 bytes) and
  `EncJWK` (`use:enc` JWK with RFC 7638 thumbprint kid) (SDKP-006)
- `testdata/bound-v1-decrypt.json` — committed bound decrypt fixture
  (never under `testdata/golden`; regenerate with
  `go test ./envelope -run TestBoundDecryptVector -update`)
- `envelope_test.go` — RFC 8037 A.6 vector, round trip byte-identical, tamper deny
- `jwks_test.go` — `SelectEncKey` discovery and fail-closed cases
- bound tests: `bound_test.go`, `bound_fresh_test.go`, `bound_nonce_test.go`,
  `bound_replay_test.go`, `bound_vector_test.go`, `bound_fixture_test.go`
- `resolver_test.go`, `keys_test.go`, `select_test.go`, `expect_test.go`
- `fuzz_test.go` — `FuzzOpen` target

**Built by**: `docs/tasks/02-inbound-trust.md`.
