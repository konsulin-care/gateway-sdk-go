# ADR 006: Caller Key Custody

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

Every party authenticates with its own signing key (`ks-party+jwt`) and
optionally holds an X25519 key for the JWE envelope. A client library that
accepts, generates, stores, or persists private keys takes on custody risk:
leaked key files, keys in env dumps, keys in logs, keys serialized into
config. The gateway's threat model assumes the *party* owns its keys; the SDK
must not quietly become a key manager.

## Decision

**Key custody stays with the caller.**

- Callers pass a `crypto.Signer` (Ed25519, or ECDSA P-256 for ES256) into
  `client`/`auth` options; envelopes open through a caller-implemented
  `Decrypter` interface over the caller's X25519 private key (PROPOSAL §7).
- The SDK **never generates, stores, rotates, serializes, or logs** private
  keys — no key material in options as raw bytes, none in env reads, none
  written to disk (PROPOSAL §5 non-goal: no key custody).
- The `kid` is always the RFC 7638 thumbprint of the *public* key, derived by
  the SDK — never a configured value, never derived from private material.
- Key generation exists only in `gatewaytest` (test fixtures, generated per
  run) and never in non-test code paths.
- Logging rule: the SDK logs method/path/status/`request_id`/`kid`/`typ` only
  — by construction no private key can be logged because none is ever held.

## Consequences

**Positive:**
- Small attack surface: no key material at rest in the SDK, none in memory
  beyond the `Signer`/`Decrypter` interface boundary.
- No key logging or persistence by construction, not by review.
- Callers plug their own HSM/KMS/agent: anything implementing `crypto.Signer`
  works, including remote signers.

**Negative:**
- Callers must generate, rotate, and back up keys themselves — mistakes there
  are theirs; mitigated by README recipes and the threat-model docs (phase 4).
- Exotic signer implementations (e.g., networked KMS) add latency per sign —
  outside the SDK's <1 ms p95 budget, which covers local signers only.
