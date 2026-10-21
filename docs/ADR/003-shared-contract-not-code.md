# ADR 003: Shared Contract, Not Code

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

The gateway (Go, gateway-adjacent) and the AGPL backend both need to agree on
the wire contract: token kinds, claims, JWE envelope, error envelopes, route
shapes. The backend originally grew an in-repo gateway client, which couples
the contract to one repo's release cadence and puts the client under AGPL.
Importing one side's Go types into the other would also drag licenses and
release trains across the boundary (ADR-001).

## Decision

**The shared artifact between gateway, backend, and SDK is the contract, not
code.**

- The contract is the gateway's Bruno collections plus its normative sections
  (*Token Kinds*, *Recipient Verification Rules*, *JWE Envelope*, *Gateway
  Key Rotation*) — the top of the authority chain in `AGENTS.md`.
- The gateway **never imports** `github.com/konsulin-care/gateway-sdk-go`, and
  this module **never imports** the gateway or the backend.
- Wire types are hand-written in `wire` from the contract — no codegen, no
  OpenAPI toolchain, no copying of gateway/backend structs.
- "Gateway importing `wire`" (to dedupe type drift with the backend adapter)
  is deferred to the gateway side and would break this rule; it stays an open
  decision in PROPOSAL §15 and would need a gateway-side ADR.
- Drift between the independently written implementations is caught by the
  golden-vector mirror (ADR-004) and the conformance runner, not by sharing
  Go code.

## Consequences

**Positive:**
- Clean licensing boundary (MIT SDK, AGPL backend, gateway untouched).
- Each side evolves and releases independently; no import cycles across repos.
- Contract changes are explicit: a PR to the gateway contract, then mirrored
  vectors, then SDK adaptation — an auditable trail.

**Negative:**
- Type and check duplication across repos — two implementations of the same
  contract can drift silently without the lockstep mechanisms.
- A wire-shape change costs at least two PRs (gateway, SDK) plus a vector
  mirror; accepted as the price of decoupling.
