# ADR 002: Stdlib-Only Runtime

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

The SDK hand-implements compact JWS (RFC 7515/7518), JWK/JWKS parsing
(RFC 7517), RFC 7638 thumbprints, and compact JWE (`ECDH-ES` + `A256GCM` over
X25519 with the SP 800-56A Concat KDF). Mature JOSE libraries exist
(`go-jose`, `golang.org/x/crypto`, `lestrrat-go/jwx`), and hand-rolling crypto
plumbing is a known risk class (PROPOSAL §14).

## Decision

**Non-test code imports the standard library or this module only. The only
third-party dependency is testify, allowed test-only.** Banned from all code
paths: `go-jose`, `golang.org/x/crypto`, `lestrrat-go/jwx`. Enforced by
depguard (`.golangci.yml`) and `qc --deps`.

**Reasons for banning JOSE libraries:**
- **X25519 ECDH-ES not covered by go-jose** — the gateway's normative JWE
  Envelope mandates `ECDH-ES` + `A256GCM` over X25519 (RFC 8037); go-jose does
  not cover that key-agreement path, so we would need custom code anyway.
- **Byte-exact header control for SDK-AUTH-C01** — the golden vector requires
  reproducing a committed `ks-party+jwt` byte for byte, which means total
  control over protected-header serialization; library encoders do not
  guarantee that determinism.
- **Parse attack surface** — a stdlib-only dependency graph is auditable in
  one page (PROPOSAL §8 threat model, item 7: supply chain).

**Mitigations for owning the plumbing:**
- RFC test vectors in CI: RFC 8037 A.4 and A.6 (X25519 / ECDH-ES envelope),
  RFC 7515 A.3 (JWS), RFC 7638 3.1 (thumbprint).
- Fuzz targets on JWS/JWKS/JWE parsers and error-envelope decoding.
- External review before v0.1.0 (PROPOSAL §14).

## Consequences

**Positive:**
- Auditable, minimal dependency graph; reproducible builds.
- Byte-exact control over every serialized byte (SDK-AUTH-C01, golden
  vectors) without fighting a library encoder.
- No upstream gaps on the X25519 envelope path.

**Negative:**
- We own the crypto plumbing and its long-term maintenance.
- New JOSE features (e.g., ES256 envelopes) cost real implementation effort.
- Mitigated by the RFC vectors, fuzzing, and pre-v0.1.0 external review; a
  library reversal would need a new ADR.
