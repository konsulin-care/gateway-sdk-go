# ADR 004: Golden Vectors Are a Read-Only Mirror

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

Byte-exact conformance (SDK-AUTH-C01, the six token kinds, settlement
fixtures) requires the SDK to verify against the exact artifacts the gateway
produces. The gateway owns the vectors; the SDK needs them in-repo for offline
tests. Editing a vector locally would silently redefine the contract this SDK
claims to verify.

## Decision

`testdata/golden/` is a **read-only, verbatim mirror** of the gateway's
vectors (PROPOSAL §11).

- **Mirrored set** (verbatim copies): `gateway-jwks.json`; `ks-access.json`,
  `ks-approval.json`, `ks-delivery.json`, `ks-event-service-result.json`,
  `ks-party.json`, `ks-result.json`; `settlement-expired-buyer.json`,
  `settlement-expired-provider.json`, `settlement-paid-buyer.json`,
  `settlement-paid-provider.json`; and `testonly-party-private.key` — the
  party key so SDK-AUTH-C01 can prove byte-exact `ks-party` signing.
- **Never mirrored**: `testonly-gateway-signing-private.key` stays in the
  gateway repo only; the SDK verifies with public JWKS. The gateway's own
  `testdata/golden/README.md` is instructions, not a vector — it stays
  gateway-side.
- This repo **never edits vectors locally**. If a vector looks wrong, the fix
  happens at the gateway and flows here by mirroring.
- **Regeneration happens only at the gateway**; the full set is mirrored here
  (phase 1: `scripts/mirror-golden.sh`), then the SDK ships a new tag.
- Either side drifting turns one CI red (lockstep). Contract-affecting changes
  update `COMPATIBILITY.md` (gateway ↔ SDK ↔ conformance-runner) in the same
  PR (ADR-009).

## Consequences

**Positive:**
- The mirrored set is ground truth: green tests mean the SDK matches the
  gateway byte for byte, not a locally adjusted expectation.
- Drift detection is automatic — CI fails on either side.
- No gateway signing key ever exists in this repo (least secret spread).

**Negative:**
- Vector updates are all-or-nothing mirror passes; local experimentation with
  a changed vector requires a gateway-side change first.
- A gateway vector bug blocks SDK work until the gateway regenerates —
  accepted; the alternative (local edits) would break the authority chain.
