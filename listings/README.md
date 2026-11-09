# listings

**Purpose**: listing routes per PRD §9.6 — `Create`
(`POST /v1/listings`, capability `listing:enlist`, `Idempotency-Key` required)
and `List` (`GET /v1/listings`, public, read — no idempotency key). The read accepts
optional GWP-005 query filters — `ListOption` values `WithName`,
`WithProviderPartyID`, `WithInvocation` (an empty value sets no query
parameter) — and `FindByName` (SDKP-007) resolves the single active
listing by provider + name, failing closed unless exactly one row
matches. `List` response shape: `endpoint_url` is returned only for
`invocation: commodity` listings and **omitted for `invocation: webhook`
rows** (the public read never exposes a provider endpoint); `metering`
(`gateway` | `provider`) is always present.

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002; SDKP-007, GWP-005
(listing filters, `FindByName`).

**Files** (actual):
- `listings.go` — `Client`, `New(cli)`, `Create`, `List(ctx, ...ListOption)`,
  `FindByName` methods (context, `*wire.Error`)
- `filter.go` — `ListOption`, `WithName`, `WithProviderPartyID`,
  `WithInvocation`, and `Client.FindByName`
- `doc.go` — package doc
- `listings_test.go` — route tests against `gatewaytest` fakes;
  `TestListOmitsEndpointURLForWebhookRows` and
  `TestListDecodesMeteringOnEveryRow` pin the §9.6 route-shape note
- `filter_test.go` — filter query params and `FindByName` exactly-one-match
  behavior

**Built by**: `docs/tasks/03-client-and-routes.md`.
