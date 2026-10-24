# Phase 3 — Client Core & Routes

## Objective

Ship the outbound half of the SDK: `client` core (functional options,
transport, retry with fresh signing, stable idempotency), every §9.6 route
as one typed method (including the `gateway` package), the `wire` route
DTOs, and `gatewaytest` fake handlers for each route. Exit: **§9.6
checklist complete against `gatewaytest`, SDK-RETRY-C01 green, race
clean**.

## Ground rules

Each checklist item is one `SDK-*` behavior: the behavior, its accept/deny
expectation, and the test that proves it. TDD — write the named failing
test first, then implement. Items marked **landed** already have green
proving tests (`wire` constants, `GW-*` catalog, retry classification) —
keep them green while extending. Every test runs offline and reads only
in-module paths; `../gateway/docs/api/` is an authoring-time reference for
re-checking the route table, never a test dependency (AGENTS.md). Re-run
`go test -race ./...` and `mise run qc` after each item.

## Depends on

- `docs/tasks/.archive/01-foundation-test-kit.md` (landed: `wire` error
  catalog + constants, `auth` signing, `gatewaytest` fakes and
  deterministic `ReplayCache`).
- `docs/tasks/02-inbound-trust.md` is independent of this phase and may
  run in parallel; both merge before phase 4.

## Checklist

### `SDK-CLIENT-001` — one `Client`, functional options

- [ ] **Behavior**: `WithBaseURL`, `WithSigner`, `WithHTTPClient`,
  `WithInsecureTransport`, `WithReplayCache`, `WithLogger`, `WithRetry`;
  every method takes `context.Context`.
- **Accept**: a fully configured client issues context-bound calls with
  the injected transport/signer/logger.
- **Deny**: an option not applied is a construction failure, not a silent
  default.
- **Proving test**: `TestClientEveryOptionAppliedWithContext`.

### `SDK-CLIENT-002` — generated `Idempotency-Key` (ADR-011)

- [ ] **Behavior**: generate an `Idempotency-Key` for every create the
  caller does not supply; stable across retries of that create; a new key
  after a terminal 402 (`GW-HOOK-006`) or any body change; caller-supplied
  keys pass through untouched.
- **Accept**: one logical create keeps one key across all attempts; two
  creates get distinct keys.
- **Deny**: a 402 outcome or a changed body never reuses the key (422
  `GW-HOOK-008` otherwise).
- **Proving tests**: `TestIdempotencyKeyStableAcrossRetries`,
  `TestIdempotencyKeyNewAfter402AndBodyChange`.

### `SDK-CLIENT-003` — error surfacing

- [ ] **Behavior**: every non-2xx surfaced as `*wire.Error` parsed from
  `{error: {code, message, request_id}}`, preserving `code` and
  `request_id`.
- **Accept**: a gateway error body decodes to `*wire.Error` with both
  fields intact (envelope decode: `TestDecodeErrorEnvelope`, **landed**).
- **Deny**: a non-envelope body never panics or fabricates a code.
- **Proving tests**: `TestClientSurfacesWireErrorFromResponse`
  (client-level; envelope parsing `TestDecodeErrorNonEnvelope` landed).

### `SDK-CLIENT-C01` — zero options fail at construction

- [ ] **Behavior**: no silent defaults to production URLs.
- **Accept**: n/a — construction success requires explicit options.
- **Deny**: a zero-option `Client` errors at construction.
- **Proving test**: `TestClientZeroOptionsFailsConstruction`.

### `SDK-RETRY-001` — fresh sign per attempt, stable key per create

- [ ] **Behavior**: every attempt signs fresh (new `jti`, new `iat` —
  `TestSignPartyAttemptFreshJtiPerAttempt`, **landed**);
  `Idempotency-Key` constant across attempts of one logical create.
- **Accept**: retries re-sign through the same path with a new `jti`.
- **Deny**: no attempt reuses a previous `jti`; no retry changes the key
  (ADR-011).
- **Proving test**: `TestClientRetryResignsWithFreshJtiSameKey`.

### `SDK-RETRY-002` — retryable class (**landed** classification)

- [ ] **Behavior**: network errors (dial/timeout/reset), `409
  idempotency_in_progress` (`GW-API-002`), `429` (`GW-RATE-001`,
  `GW-ADMIN-003`, `GW-IDX-011`, `GW-STS-005`), `502`, `503`
  (`GW-HOOK-009`), `504`; catalog-disposition driven (`wire.Retryable`);
  bounded exponential backoff with jitter, honoring `Retry-After`; an
  unrecognized code falls back to status classes (ADR-012).
- **Accept**: every retryable row above classifies retryable; a retry
  backs off and honors `Retry-After`.
- **Deny**: a network-error retry is bounded — it never loops
  indefinitely.
- **Proving tests**: `TestRetryClassification`,
  `TestRetryClassificationMatchesCatalog` (**landed**);
  `TestClientRetryBackoffHonoursRetryAfter` (client, planned).

### `SDK-RETRY-003` — terminal class (**landed** classification)

- [ ] **Behavior**: `400`, `401`, `402` `GW-HOOK-006` (terminal **and**
  mandates a new `Idempotency-Key`), `403` `capability_denied` /
  `GW-PARTY-010` / `GW-PARTY-011`, `404`, `409` `GW-PARTY-006` (only
  `GW-API-002` makes 409 retryable), `413`, `422` `GW-HOOK-008`.
- **Accept**: terminal responses return on the first attempt; a 402
  flips the key flag.
- **Deny**: no terminal code is ever retried, including around a missing
  capability grant.
- **Proving tests**: `TestRetryClassification`,
  `TestRetry402RequiresNewIdempotencyKey` (**landed**);
  `TestClientNeverRetriesTerminal403` (client, planned).

### `SDK-RETRY-C01` — retry sequence semantics

- [ ] **Behavior**: composite criterion of §9.8.
- **Accept**: a 409→200 sequence replays with the **same**
  `Idempotency-Key` and a **different** `jti`.
- **Deny**: a 403 returns on the first response — no second attempt.
- **Proving tests**: `TestRetry409To200ReplaysSameKeyNewJti`,
  `TestRetry403TerminalOnFirstResponse` (against `httptest` sequences).

### `SDK-API-001` — every §9.6 row exists

- [ ] **Behavior**: one typed method per row with request/response
  structs in `wire`, context support, typed errors; `parties.Rotate`
  signs with the party's **current active key** (a superseded
  grace-window key is rejected gateway-side with `GW-PARTY-011`).
- **Accept**: every table row resolves to a tested method; `listings.List`
  decodes `metering` and treats `endpoint_url` as absent for
  `invocation: webhook` rows (§9.6 route-shape note).
- **Deny**: any row without a method/DTO fails the table test; exclusions
  (admin, `GET /v1/webhooks/dlq`, `auth:provider` inbound, admin
  bootstrap trio) stay unimplemented.
- **Proving tests**: `TestEveryRouteRowHasTypedMethod`,
  `TestListingsListOmitsEndpointURLForWebhookRows`.

### `SDK-API-002` — idempotency encoding + no 4xx retry

- [ ] **Behavior**: `Idempotency-Key` on rows marked required; 4xx
  rejected without retry.
- **Accept**: each required row sends the header (generated or
  caller-supplied).
- **Deny**: a 4xx response is returned, never retried.
- **Proving tests**: `TestIdempotencyKeyEncodedOnRequiredRows`,
  `TestClient4xxNeverRetried`.

### `SDK-WIRE-001` — route DTOs byte-match the contract

- [ ] **Behavior**: DTOs for every request/response body; JSON tags match
  the Bruno examples byte-for-byte — including the service-receipt body
  `{webhook_id, status, quota_remaining, body}` (`quota_remaining` =
  provider `X-Quota-Remaining` verbatim string or `null`) and the
  `X-Quota-Remaining` response-header relay on `webhooks.Sync`.
- **Accept**: each DTO marshals field names exactly as the examples.
- **Deny**: a renamed/missing field fails the shape test — no
  `omitempty` surprises on required fields.
- **Proving test**: `TestDTOTagsMatchBrunoExamples`.

### `SDK-WIRE-002` — typ/purpose/capability/kind constants (**landed**)

- [ ] **Behavior**: six `typ` constants; seven purposes in PRD order
  (`webhook-delivery`, `settlement-notification`, `service-result`,
  `payment-required`, `service-receipt`, `webhook-result`, `admin-auth`);
  capability catalog; token-kind table with required vs conditional
  claims (`user_ref`, `payment_id` conditional on `ks-delivery+jwt`).
- **Accept**: constants and table match §9.7; `TokenKindTable()`/
  `KindForTyp()` return deep copies.
- **Deny**: an unknown `typ` → `KindForTyp` false; mutating a returned
  slice must not corrupt the table.
- **Proving tests**: `TestPurposeConstants`, `TestPurposesList`,
  `TestTokenKindTable`, `TestTokenKindConditionalSplit`,
  `TestTokenKindTableDeepCopiesBothSlices` (**landed**).

### `SDK-WIRE-003` — `*wire.Error` + full `GW-*` catalog (**landed**)

- [ ] **Behavior**: `*wire.Error{Code, Message, RequestID, Status}` as the
  one error type; sentinels for `errors.Is/As`; the full `GW-*` catalog
  as data (`wire.LookupCode`, `wire.Codes` — code, HTTP status,
  disposition) covering the hardening codes (`GW-PARTY-010/011`,
  `GW-HOOK-006/008/009`, `GW-RATE-001`, `GW-IDX-011`, `GW-STS-005`).
- **Accept**: every code looks up with status + disposition; sentinel
  `errors.Is` matches decoded errors (aliases included).
- **Deny**: an unknown code returns `false`; catalog status can never
  drift from a sentinel's status.
- **Proving tests**: `TestDecodeErrorEnvelope`, `TestErrorsIsSentinels`,
  `TestCodeCatalogLookup`, `TestCodeCatalogComplete` (**landed**).

### `SDK-WIRE-004` — forward-compatible decoding (ADR-012)

- [ ] **Behavior**: unknown JSON fields and unknown claim names are
  ignored — never an error, never a deny; an unrecognized `GW-*` code
  classifies from HTTP status instead of failing. Selection stays
  fail-closed: unknown `typ`/`kid` deny (covered in `verify`, task 02).
- **Accept**: a response/claim set carrying new gateway fields decodes
  and known fields keep their values.
- **Deny**: decoding never whitelists field names; a status with an
  unknown code still classifies (no decode error).
- **Proving test**: `TestDecodeIgnoresUnknownFieldsAndCodes`.

### `SDK-TEST-001` (extension) — fake handler per route

- [ ] **Behavior**: `gatewaytest` fake handlers for every §9.6 route
  with error-envelope responses, idempotency replay, and 409/429/5xx
  sequences for retry tests.
- **Accept**: each row has a fake that replays idempotent creates and
  serves the scripted sequences.
- **Deny**: a row without a fake fails the coverage test.
- **Proving test**: `TestGatewaytestHandlersCoverRouteTable`.

## Files to create/edit

Create:

- `client/client.go`, `client/options.go`, `client/retry.go`,
  `client/idempotency.go`, `client/client_test.go`
- `wire/dto_parties.go`, `wire/dto_identities.go`,
  `wire/dto_approvals.go`, `wire/dto_listings.go`,
  `wire/dto_payments.go`, `wire/dto_webhooks.go`, `wire/dto_test.go`
- `parties/parties.go`, `parties/parties_test.go`
- `identities/identities.go`, `identities/identities_test.go`
- `approvals/approvals.go`, `approvals/approvals_test.go`
- `listings/listings.go`, `listings/listings_test.go`
- `payments/payments.go`, `payments/payments_test.go`
- `webhooks/webhooks.go`, `webhooks/webhooks_test.go`
- `gateway/gateway.go`, `gateway/gateway_test.go`
- `gatewaytest/handlers.go` (+ tests) — fake handler per §9.6 route

Edit:

- `client/README.md`, `wire/README.md`, `gatewaytest/README.md` planned
  lists if files split differently (files ≤ 300 lines)

## Definition of Done

- [ ] Every checklist item's proving tests green; accept and deny
      expectations both asserted.
- [ ] All §9.6 rows implemented and tested against `gatewaytest`
      (exclusions per the coverage rule: admin routes,
      `GET /v1/webhooks/dlq`, `auth:provider` inbound, admin bootstrap
      trio).
- [ ] SDK-RETRY-C01 green: 409→200 same `Idempotency-Key` / different
      `jti`; 403 terminal on first response; `Retry-After` honored; a 402
      mandates a new key.
- [ ] SDK-WIRE-001: JSON field names match the Bruno examples
      byte-for-byte for every DTO.
- [ ] `go test -race ./...` clean (no races under concurrent client use),
      zero network, no test reading outside the module; `mise run qc`
      green.
- [ ] Every new exported symbol has a doc comment; files ≤ 300 lines;
      complexity ≤ 15.

## Open items

- The §9.6 coverage rule is explicit-exclusion, not path-prefix: re-check
  the route list against the gateway's `docs/api/` collection
  (authoring-time) at phase end in case the gateway added party-facing
  routes since bootstrap.
- `WithInsecureTransport` + `gatewaytest` runs over `http` locally —
  confirm the construction-time guard still fails closed for non-local
  base URLs.
