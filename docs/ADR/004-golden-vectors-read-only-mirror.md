# ADR 004: Golden Vectors Are a Read-Only Mirror

**Status:** Accepted (amended 2026-10-23: mechanism — manifest pinning
replaces the live sibling comparison)
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

Byte-exact conformance (SDK-AUTH-C01, the six token kinds, settlement
fixtures) requires the SDK to verify against the exact artifacts the gateway
produces. The gateway owns the vectors; the SDK needs them in-repo for offline
tests. Editing a vector locally would silently redefine the contract this SDK
claims to verify. The original mechanism compared the mirror against a live
`../gateway` checkout in CI — that made every build depend on a private
sibling repository that forks and external CI never have, so the comparison
silently skipped exactly where it was supposed to guard.

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
  by `scripts/mirror-golden.sh`, which in the same run rewrites
  `testdata/golden/MANIFEST.json` — one SHA-256 per mirrored vector plus the
  gateway commit mirrored from — then the SDK ships a new tag.
- **Manifest pinning (replaces the live sibling comparison).** CI and the
  unit suite never read `../gateway` or any path outside this module. They
  verify the committed vectors against `MANIFEST.json` through
  `gatewaytest/manifest.go`, which fails closed on a hash mismatch, a missing
  entry, or an on-disk vector absent from the manifest (PROPOSAL §11,
  SDK-TEST-001). Byte-fidelity is proven offline on every run, in any clone.
- **Drift detection is out-of-band, not CI.** `scripts/mirror-golden.sh
  --check` — exposed as the local-only `mise run qc --mirror-check` —
  compares the mirror against a developer's sibling gateway checkout when
  one exists, and is **skipped, not failed, when it is absent**. No CI job
  touches the gateway; contract drift surfaces at the next mirror run or
  when a developer runs the check locally. Contract-affecting changes
  update `COMPATIBILITY.md` (gateway ↔ SDK ↔ conformance-runner) in the
  same PR (ADR-009).

## Consequences

**Positive:**
- The mirrored set is ground truth: green tests mean the SDK matches the
  gateway byte for byte, not a locally adjusted expectation.
- Offline CI proves fidelity against the pinned manifest on every run, in
  any clone — no private checkout, no skipped guard, no fork/CI asymmetry.
- A locally edited vector fails closed (hash mismatch in `gatewaytest`),
  so the "never edit locally" rule is enforced, not just documented.
- No gateway signing key ever exists in this repo (least secret spread).

**Negative:**
- Vector updates are all-or-nothing mirror passes; local experimentation with
  a changed vector requires a gateway-side change first.
- The manifest and the vectors must be regenerated together — a stale
  manifest fails closed, which is the point, but it means the mirror script
  is the only supported update path.
- Gateway drift is detected out-of-band (local `qc --mirror-check` or the
  next mirror run), not by CI on either side — accepted in exchange for a
  suite that needs no sibling checkout.
- A gateway vector bug blocks SDK work until the gateway regenerates —
  accepted; the alternative (local edits) would break the authority chain.
