# ADR 016: Recipient enc-Key Resolver (SDKP-002)

**Status:** Accepted
**Date:** 2026-10-25
**Deciders:** Konsulin central

## Context

`envelope.SelectEncKey` selects the decryption key by the `kid` in the
JWE header, but a *sender* does not know the recipient's key id in
advance — before sealing it must pick the current `use:enc` key out of
the recipient's party JWKS (`GET /v1/parties/{id}/jwks`, SDK-ENV-002).
Re-fetching per seal would put a network call on the hot path and invite
refetch storms on rotation; caching without a bound would serve stale
keys forever after a rotation. The resolver must also reach the network
without `envelope` importing `parties`: the import table (ADR-005,
docs/ARCHITECTURE.md §2) gives `envelope` only `wire` and
`internal/jwk`, and a route-package edge would couple JWE to HTTP
transport. One decision pins selection, caching, the refetch bound, and
the boundary.

## Decision

- **Single `use:enc` selection.** Every selection goes through
  `envelope.SelectRecipientEncKey`: the document must hold exactly one
  OKP/X25519 `use:enc` key. Zero keys ("no use:enc key in JWKS") or more
  than one ("ambiguous") fails closed with a nil key — selection is
  enumeration over the JWKS encryption keys, never by `alg` or a
  sender-chosen hint. No `jwk` type is re-exported: only
  `crypto/ecdh` and the `kid` string cross the API (ADR-005).
- **TTL cache.** `envelope.EncKeyResolver` keeps a per-party entry
  (`NewEncKeyResolver(fetch, ttl, clock)`). `Resolve` serves the selected
  key from cache for the whole TTL — a cache hit makes no fetch call —
  and fetches only when the entry is missing or older than `ttl`. Each
  party has its own entry and timestamps, so parties never evict each
  other. A non-positive TTL disables caching; a nil clock means
  `time.Now` (tests inject a deterministic clock so TTL and rate-limit
  expiry are reproducible).
- **Rate-limited refetch.** `Refresh` forces one refetch after a
  seal/open failure — even inside the TTL, so a rotated recipient key is
  picked up without waiting — but at most one Refresh attempt runs per
  TTL window per party (the `refresh` timestamp records every attempt,
  success or failure). A second Refresh inside the window never fetches
  again: it serves the cached key, or fails closed when nothing is
  cached. Repeated `Refresh` after a failure therefore never loops into
  a refetch storm — the same bounded-refetch posture as the inbound
  unknown-`kid` rule (ADR-007). The TTL doubles as the rate-limit
  window: one forced refetch per `ttl` per party.
- **Fetch-func boundary.** The resolver fetches only through the
  caller-supplied `FetchFunc(ctx, partyID) ([]byte, error)` — the raw
  JWKS document as served by `GET /v1/parties/{id}/jwks`. `envelope`
  never imports `parties` or any route package: the caller wires
  `parties.Client.JWKS` (or a test double, or a fixture file) into the
  constructor. This keeps the import DAG acyclic per ADR-005 and keeps
  JWE seal/open independent of HTTP transport. A nil fetch makes every
  `Resolve`/`Refresh` fail closed with an error rather than panic.
- **Fail closed, invalidate on failure.** Any failure — a fetch error or
  a document that fails selection — returns a nil key and clears the
  cached entry, so a stale key is never served after a failure.
  Concurrency-safe: one mutex serializes all lookups, so concurrent
  misses never stampede the fetch.

## Consequences

**Positive:**
- Senders seal without knowing the recipient's `kid`: one selection
  rule, one cached key per party, rotation picked up by TTL expiry or a
  single bounded `Refresh`.
- Refetch is bounded by design — at most one forced fetch per TTL window
  per party — so a failing recipient endpoint cannot cause a storm.
- The fetch-func boundary keeps `envelope`'s import set at `wire` +
  `internal/jwk` (ADR-005) while still supporting live gateway fetches,
  offline fixtures, and deterministic test doubles behind one signature.

**Negative:**
- The caller must wire the fetch function; a resolver constructed with
  nil fetch fails closed on every call — accepted (explicit wiring beats
  a hidden network default).
- The cache holds a recipient's *public* key per party for up to a TTL
  after rotation; within the window a seal may use the previous key.
  Callers needing immediate rotation pickup call `Refresh` once — still
  rate-limited — accepted as the availability/latency trade.
- Fail-closed invalidation means a transient fetch error drops the
  cached key: the next call pays a fetch — accepted (fail closed beats
  serving a key whose freshness is unknown).
