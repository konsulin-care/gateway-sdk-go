# ADR 005: Package Layout and Import Rules

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

Go libraries have two common layouts: `pkg/` + `internal/` (old v1-era
fashion) and public packages at the module root with `internal/` for
non-public code (modern convention). The SDK also needs JOSE primitives
(JWS encode/verify, JWK/JWKS parse, thumbprints) that must stay out of the
public API surface, and the dependency graph must stay auditable per ADR-002.

## Decision

- **Go library layout**: public packages at the module root, **no `pkg/`**;
  non-public code under `internal/`. Files ≤ 300 lines everywhere.
- **JOSE split**: `internal/jws` (RFC 7515/7518 compact JWS — alg checks,
  ES256 DER↔raw R||S) and `internal/jwk` (RFC 7517 JWK/JWKS parse, RFC 7638
  thumbprint) — separate packages on separate RFCs, both hand-written on the
  stdlib (ADR-002), both **never re-exported**. Only `auth`, `verify`, and
  `gatewaytest` may import them; nothing outside them implements JWS/JWK
  primitives. `envelope` is deliberately **not** built on `internal/jws` —
  JWE goes through `crypto/ecdh` + `crypto/aes` + `wire` only.
- **Public surface**: `wire` (DTOs, typ/capability constants, `*wire.Error` —
  the contract leaf), `auth`, `client`, `verify`, `identity`, `envelope`,
  route packages (`gateway`, `parties`, `identities`, `approvals`, `listings`,
  `payments`, `webhooks`), and `gatewaytest` (test kit).
- **Non-public**: `internal/adminboot` (admin bootstrap for conformance setup
  — the operator surface never enters the public client, PROPOSAL §5),
  `internal/conformance` (shared cases), `internal/integration` (offline e2e,
  no build tag), `cmd/conformance` (thin `main`).
- **Import table** (normative, full table in `docs/ARCHITECTURE.md` §2):
  non-test code imports stdlib or this module only; `wire`, `internal/jws`,
  `internal/jwk` are stdlib-only leaves; route packages layer on
  `client` + `auth` + `wire`; `client` imports no route packages;
  `gatewaytest` is imported only by test files and the conformance runner.
- Enforced by depguard and `qc --deps` — rules, not conventions.

## Consequences

**Positive:**
- The public API surface is explicit and small; internal plumbing can be
  refactored without breaking consumers.
- No `pkg/` ambiguity: importable means public.
- The jws/jwk split mirrors the RFC split, keeps each parser fuzzable in
  isolation, and prevents a monolithic `jose` package from growing.

**Negative:**
- Thin route packages mean many small packages to navigate — accepted for a
  flat, grep-friendly library layout.
- Re-exporting jws/jwk later (if ever wanted) is a breaking public-API
  decision and would need a new ADR.
