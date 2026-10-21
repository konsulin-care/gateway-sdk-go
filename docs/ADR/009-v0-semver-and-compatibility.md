# ADR 009: v0 Semver and Compatibility

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

The wire contract is still moving (payment sessions, envelope details), and
the SDK is pre-v0.1.0. Consumers (the backend adapter, third parties) need a
stability signal; pretending stability with 1.x now would either freeze the
contract prematurely or force silent breaks later. Version skew between
gateway, SDK, and conformance runner is a known risk (PROPOSAL §14).

## Decision

- **Semver v0.x**: minors may break, but never silently — every break
  carries a CHANGELOG entry and a `COMPATIBILITY.md` update **in the same
  PR** (PROPOSAL §12). Wire-shape changes are breaks even in v0.
- **`COMPATIBILITY.md`**: a table of gateway version ↔ SDK version ↔
  conformance-runner version. Consumers pin SDK tags and consult the table
  before upgrading. Added before v0.1.0 (phase 4).
- **No tag without green CI + conformance**: release gate per
  `docs/ARCHITECTURE.md` §7 — `mise run qc` green, golden + RFC vectors
  green, offline e2e green, conformance green against the throwaway gateway.
- **Conformance runner versioned with the module** (`v0.x` tags); the gateway
  pins the runner version in `qc --flow` once v0.1.0 exists (gateway-side,
  SDK-CONF-003, M5 follow-up).
- At 1.0.0 the policy tightens to strict semver — a future ADR marks the
  transition.

## Consequences

**Positive:**
- Honest stability window: breaks are allowed while the contract settles, but
  they are documented and traceable via the compatibility table.
- Consumers pinning tags get a reproducible contract; skew problems show up
  in the conformance pin, not in production.
- Release discipline is mechanical: no green CI + conformance, no tag.

**Negative:**
- v0 consumers must read the CHANGELOG per minor upgrade — the table is the
  mitigation, and it is a maintenance burden on every contract-affecting PR.
- Gateway-side conformance pinning lags until v0.1.0 (M5); until then drift
  is caught only by the SDK's own lockstep CI.
