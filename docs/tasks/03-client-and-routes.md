# Phase 3 — Client Core & Routes

## Objective

Ship the outbound half of the SDK: `client` core (functional options,
transport, retry with fresh signing, stable idempotency), every §9.6 route
as one typed method (including the `gateway` package), the `wire` route
DTOs, and `gatewaytest` fake handlers for each route. Exit: **§9.6
checklist complete against `gatewaytest`, SDK-RETRY-C01 green, race
clean**.

## Depends on

- `docs/tasks/01-foundation-test-kit.md` (`wire` error catalog + constants,
  `auth` signing, `gatewaytest` v1 fakes and deterministic ReplayCache).
- `docs/tasks/02-inbound-trust.md` is independent of this phase and may
  run in parallel; both merge before phase 4.

## Requirement IDs

- `SDK-CLIENT-001` — one `Client`, functional options `WithBaseURL`,
  `WithSigner`, `WithHTTPClient`, `WithInsecureTransport`,
  `WithReplayCache`, `WithLogger`, `WithRetry`; every method takes
  `context.Context`.
- `SDK-CLIENT-002` — generate `Idempotency-Key` for every create the
  caller does not supply; stable across retries of that call.
- `SDK-CLIENT-003` — every non-2xx surfaced as `*wire.Error` parsed from
  `{error: {code, message, request_id}}`, preserving `code` and
  `request_id`.
- `SDK-CLIENT-C01` — zero-option `Client` fails at construction (no
  silent defaults to production URLs).
- `SDK-RETRY-001` — fresh sign per attempt (new `jti`, new `iat`);
  `Idempotency-Key` constant across attempts of one logical create.
- `SDK-RETRY-002` — retryable: dial/timeout/reset, `409
  idempotency_in_progress`, `429`, `502`, `503`, `504`; bounded
  exponential backoff with jitter, honoring `Retry-After`.
- `SDK-RETRY-003` — terminal, never retried: `400`, `401`, `402`, `403`
  (incl. `capability_denied`), `404`, `413`, `422`.
- `SDK-RETRY-C01` — 409→200 replays with the same `Idempotency-Key` and a
  different `jti`; a 403 returns on the first response.
- `SDK-API-001` — every §9.6 row exists with request/response structs in
  `wire`, context support, typed errors; the table is the coverage
  checklist.
- `SDK-API-002` — `Idempotency-Key` encoded on the rows marked required;
  4xx rejected without retry.
- `SDK-WIRE-001` — DTOs for every request/response body; JSON tags match
  the Bruno examples byte-for-byte in field names.
- `SDK-TEST-001` (extension) — `gatewaytest` fake handlers per §9.6
  route.

## Files to create/edit

Create:

- `client/client.go`, `client/options.go`, `client/retry.go`,
  `client/idempotency.go`, `client/client_test.go`
- `wire/dto_parties.go`, `wire/dto_identities.go`,
  `wire/dto_approvals.go`, `wire/dto_listings.go`, `wire/dto_payments.go`,
  `wire/dto_webhooks.go`, `wire/dto_test.go`
- `parties/parties.go`, `parties/parties_test.go`
- `identities/identities.go`, `identities/identities_test.go`
- `approvals/approvals.go`, `approvals/approvals_test.go`
- `listings/listings.go`, `listings/listings_test.go`
- `payments/payments.go`, `payments/payments_test.go`
- `webhooks/webhooks.go`, `webhooks/webhooks_test.go`
- `gateway/gateway.go`, `gateway/gateway_test.go`
- `gatewaytest/handlers.go` (+ tests) — fake handler per §9.6 route,
  error-envelope responses, idempotency replay behavior, 409/429/5xx
  sequences for retry tests

Edit:

- `client/README.md`, `wire/README.md`, `gatewaytest/README.md` planned
  lists if files split differently (files ≤ 300 lines)

## Direction (TDD)

1. **wire DTOs** — failing shape tests first: JSON marshal of each
   request/response against the Bruno examples (field names byte-exact);
   then the six `dto_*.go` files.
2. **client construction** — failing SDK-CLIENT-C01 test (zero options
   fails at construction), then `client.go` + `options.go`.
3. **idempotency** — failing test: generated key stable across retries of
   one logical create, distinct across creates; then `idempotency.go`.
4. **retry** — failing SDK-RETRY-C01 test against an `httptest` sequence
   409→200 (same `Idempotency-Key`, different `jti`) plus a 403-terminal
   case and `Retry-After` honoring; then `retry.go` with the
   retryable/terminal classes from PRD §9.8.
5. **errors** — failing test that a non-2xx body decodes into
   `*wire.Error` with `code`/`request_id` preserved (SDK-CLIENT-003).
6. **gatewaytest handlers** — failing tests per fake route (happy path +
   error envelope + idempotency replay); then `gatewaytest/handlers.go`.
7. **routes** — per package, failing route test against the fake first
   (method, path, auth placement, `Idempotency-Key` on required rows,
   context propagation, typed errors), then the method. Work the §9.6
   table top to bottom: `parties` → `identities` → `approvals` →
   `listings` → `payments` → `webhooks` → `gateway`.
8. Run `go test -race ./...` and `mise run qc` after every step.

## Definition of Done

- [ ] All 19 §9.6 rows implemented and tested against `gatewaytest`
      (checklist in PROPOSAL §9.6 ticked off, exclusions per the coverage
      rule: admin routes, `GET /v1/webhooks/dlq`, `auth:provider`
      inbound, admin bootstrap trio).
- [ ] SDK-CLIENT-C01 green: zero options fail at construction.
- [ ] SDK-RETRY-C01 green: 409→200 same `Idempotency-Key` / different
      `jti`; 403 terminal on first response; `Retry-After` honored.
- [ ] SDK-RETRY-002/003 class tests green (each retryable and terminal
      status covered); SDK-API-002 idempotency encoded on required rows,
      4xx never retried.
- [ ] SDK-WIRE-001: JSON field names match the Bruno examples
      byte-for-byte for every DTO.
- [ ] `go test -race ./...` clean (no races under concurrent client use);
      `mise run qc` green.
- [ ] Every new exported symbol has a doc comment; files ≤ 300 lines;
      complexity ≤ 15.

## Open items

- The §9.6 coverage rule is explicit-exclusion, not path-prefix: re-check
  the route list against `../gateway/docs/api/` at phase end in case the
  gateway added party-facing routes since bootstrap.
- `WithInsecureTransport` + `gatewaytest` runs over `http` locally —
  confirm the construction-time guard still fails closed for non-local
  base URLs.
