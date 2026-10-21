# webhooks

**Purpose**: webhook routes per PRD §9.6 — `Enqueue` (`POST /v1/webhooks`),
`Sync` (`POST /v1/webhooks/sync`), `Status` (`GET /v1/webhooks/{id}/status`),
`Result` (`POST /v1/webhooks/{id}/result`, single-use result ticket,
`auth:ticket`). Inbound deliveries/results arrive at the party's own endpoints
and are covered by `verify` middleware (SDK-VERIFY), not by this package.

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Planned files**:
- `webhooks.go` — `Enqueue`, `Sync`, `Status`, `Result` methods (context, `*wire.Error`)
- `webhooks_test.go` — route tests against `gatewaytest` fakes

**Built by**: `docs/tasks/03-client-and-routes.md`.
