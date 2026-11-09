# ADR 014: Shared ReplayCache Interface in wire

**Status:** Accepted
**Date:** 2026-10-24
**Deciders:** Konsulin central

## Context

Three unrelated subsystems need atomic replay dedupe: `client` reserves a
retry `jti` before network I/O (SDK-RETRY-002), `verify` consumes inbound
`jti` and `webhook_id` (SDK-VERIFY-003/004), and `envelope.OpenBound`
reserves the `(from, nonce)` pair (SDKP-001, ADR-013). Each subsystem
must accept a caller-supplied implementation — in-memory default,
Redis-backed, a test double — without any of them importing the others:
`client` must not depend on inbound trust, and `verify` must not gain an
outbound-client dependency (ADR-005 import rules). A single interface has
to exist somewhere every consumer already imports.

## Decision

- **The interface lives in `wire`.** `wire.ReplayCache`
  (`wire/replay.go`) defines `Check(ctx, scope, key, until) (bool, error)`
  and `Release(ctx, scope, key)` — atomically reserve `(scope, key)`
  until `until`, first Check fresh, later Checks a replay, any error
  denies — plus the scope constants `ScopeJTI`, `ScopeWebhookID`, and
  `ScopeNonce` so the three key spaces never collide.
- **Client and verify alias it.** `client.ReplayCache` and
  `verify.ReplayCache` are type aliases of `wire.ReplayCache`
  (`client/options.go`, `verify/replay.go`), and `verify`'s scope
  constants alias the `wire` values — one implementation satisfies every
  user with no conversion (asserted in `wire/replay_test.go`).
  `envelope` takes `wire.ReplayCache` directly.
- **The default stays in `verify`.** `verify.NewMemoryReplayCache` —
  the mutex-guarded in-process map with lazy expiry and an amortized
  sweep — remains the in-memory default behind the `Verifier`
  (`WithReplayCache` replaces it; `WithReplayRetention` defaults to 24 h
  for `webhook_id`). `wire` ships no default implementation.
- **Trade-offs accepted.** Placing the interface in `wire` trades a
  purely-DTO `wire` package for a behavioral contract: `wire` now
  documents concurrency-safety, reservation semantics, and
  fail-closed-on-error policy that it cannot itself enforce or test
  beyond compile-time conformance. In exchange, `client`, `verify`, and
  `envelope` share one interface without new import edges — defining it
  in `verify` instead would have forced `client`'s retry path to import
  inbound trust (banned by the import table) or duplicated three
  divergent interfaces. Because `wire` carries no default, a `wire`-only
  consumer must bring its own implementation; the standard default is
  reached through `verify`, which is where inbound verification already
  lives.

## Consequences

**Positive:**
- One interface, one set of scope constants, one set of semantics across
  retry `jti`, inbound `jti`/`webhook_id`, and bound-envelope nonce —
  implementations are written once and shared (including
  `gatewaytest` doubles).
- The import DAG stays acyclic and matches ADR-005: no consumer imports
  another consumer; `wire` remains the stdlib-only leaf.
- Callers keep custody of their replay store: swap the in-process
  default for Redis or a deterministic test clock without touching
  `client`, `verify`, or `envelope` signatures.

**Negative:**
- `wire` is no longer a pure data package: interface docs must stay in
  sync with three consumers' expectations (atomicity, `Release`
  semantics, deny-on-error), or a lax implementation becomes a replay
  hole that no compile-time check catches.
- `wire` alone cannot dedupe out of the box — the default living in
  `verify` means a non-verifying consumer of `wire` must supply or import
  an implementation.
- The fail-closed rule ("any error denies") is convention, not
  enforcement: a caller that ignores a `Check` error reopens replay;
  documented in the interface and asserted in each consumer's tests.
