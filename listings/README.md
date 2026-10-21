# listings

**Purpose**: listing routes per PRD §9.6 — `Create`
(`POST /v1/listings`, capability `listing:enlist`, `Idempotency-Key` required)
and `List` (`GET /v1/listings`, public, read — no idempotency key).

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Planned files**:
- `listings.go` — `Create`, `List` methods (context, `*wire.Error`)
- `listings_test.go` — route tests against `gatewaytest` fakes

**Built by**: `docs/tasks/03-client-and-routes.md`.
