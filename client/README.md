# client

**Purpose**: the `Client` core — functional options (`WithBaseURL`,
`WithSigner`, `WithHTTPClient`, `WithInsecureTransport`,
`WithReplayCache`, `WithLogger`, `WithRetry`), construction-time
transport guard (https, or `http` only for loopback hosts with
`WithInsecureTransport` — SDK-CLIENT-C01), `Idempotency-Key` generation
stable across the retries of one logical create (caller keys pass through
via `Request.WithIdempotencyKey`), bounded retry with a fresh signature
per attempt, `WithResponseMeta` observability (`ResponseMeta` with the
sent key), and typed `*wire.Error` surfacing. Route packages build on
this; this package imports none of them.

**Allowed imports** (PRD §7 dependency rules): standard library, `wire`,
`auth`.

**Related requirements**: SDK-CLIENT-001, SDK-CLIENT-002, SDK-CLIENT-003,
SDK-CLIENT-C01, SDK-RETRY-001, SDK-RETRY-002, SDK-RETRY-003, SDK-RETRY-C01.

**Files** (actual):
- `client.go` — `Client` construction (`New`; zero options fails, no
  silent defaults), `Do` request execution with the retry loop
- `options.go` — functional options, `RetryPolicy`, `ReplayCache`
  interface, `transportURL` guard (http requires opt-in + loopback host)
- `call_options.go` — per-call `Request`/`Response` and
  `Request.WithIdempotencyKey`
- `request.go` — `ResponseMeta`, `CallOption`, `WithResponseMeta`
- `retry.go` — `ErrOutcomeUnknown`, backoff with jitter, `Retry-After`,
  fresh `jti` per attempt, terminal vs retryable classes
- `idempotency.go` — generated key per logical create (UUIDv4-shaped)
- `signer.go` — `ErrNoSigner` gate; `replay.go` — jti reservation through
  the `ReplayCache` before network I/O
- `errors.go` — `outcome`, `DecodeInto` (2xx decode, unknown fields
  ignored)
- `doc.go` — package doc
- tests: `client_test.go`, `options_test.go`, `idempotency_test.go`,
  `retry_test.go` (SDK-RETRY-C01: 409→200 same key, different `jti`;
  403 terminal; `Retry-After`; race-clean parallel `Do`),
  `export_test.go` (test-only hooks)

**Built by**: `docs/tasks/03-client-and-routes.md`.
