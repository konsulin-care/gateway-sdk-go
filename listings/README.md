# listings

**Purpose**: listing routes per PRD §9.6 — `Create`
(`POST /v1/listings`, capability `listing:enlist`, `Idempotency-Key` required)
and `List` (`GET /v1/listings`, public, read — no idempotency key).
`List` response shape: `endpoint_url` is returned only for
`invocation: commodity` listings and **omitted for `invocation: webhook`
rows** (the public read never exposes a provider endpoint); `metering`
(`gateway` | `provider`) is always present.

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Files** (actual):
- `listings.go` — `Client`, `New(cli)`, `Create`, `List` methods
  (context, `*wire.Error`)
- `doc.go` — package doc
- `listings_test.go` — route tests against `gatewaytest` fakes;
  `TestListOmitsEndpointURLForWebhookRows` and
  `TestListDecodesMeteringOnEveryRow` pin the §9.6 route-shape note

**Built by**: `docs/tasks/03-client-and-routes.md`.
