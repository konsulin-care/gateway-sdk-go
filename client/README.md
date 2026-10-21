# client

**Purpose**: the `Client` core — functional options (`WithBaseURL`,
`WithSigner`, `WithHTTPClient`, `WithInsecureTransport`, `WithReplayCache`,
`WithLogger`, `WithRetry`), `Idempotency-Key` generation stable across the
retries of one logical create, bounded retry with a fresh signature per
attempt, and typed `*wire.Error` surfacing. Route packages build on this;
this package imports none of them.

**Allowed imports** (PRD §7 dependency rules): standard library, `wire`,
`auth`.

**Related requirements**: SDK-CLIENT-001, SDK-CLIENT-002, SDK-CLIENT-003,
SDK-CLIENT-C01, SDK-RETRY-001, SDK-RETRY-002, SDK-RETRY-003, SDK-RETRY-C01.

**Planned files**:
- `client.go` — `Client` construction (zero options fails), request execution
- `options.go` — functional options
- `retry.go` — backoff with jitter, `Retry-After`, fresh `jti` per attempt, terminal vs retryable classes
- `idempotency.go` — stable `Idempotency-Key` per logical create
- `client_test.go` — SDK-RETRY-C01 (409→200 same key, different `jti`; 403 terminal)

**Built by**: `docs/tasks/03-client-and-routes.md`.
