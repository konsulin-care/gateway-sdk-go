# payments

**Purpose**: payment routes per PRD §9.6 — `Create` (`POST /v1/payments`,
capability `payment:create`, `Idempotency-Key` required), `Get`
(`GET /v1/payments/{id}`), `AccessToken`
(`POST /v1/payments/{id}/access-token`, `Idempotency-Key` required). Inbound
payment callbacks are NOT here — they are covered by `verify` middleware
(SDK-VERIFY). The gateway→buyer `payment-required` and `service-receipt`
event pushes (`ks-event+jwt`, provider-metered listings) are also inbound
surfaces of `verify`, not routes of this package (PRD §9.6).

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Planned files**:
- `payments.go` — `Create`, `Get`, `AccessToken` methods (context, `*wire.Error`)
- `payments_test.go` — route tests against `gatewaytest` fakes

**Built by**: `docs/tasks/03-client-and-routes.md`.
