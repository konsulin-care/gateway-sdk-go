# approvals

**Purpose**: approval ticket routes per PRD §9.6 — `Mint`
(`POST /v1/approvals`) with capability `approval:referral` or
`approval:export:<study>`, `Idempotency-Key` required. The recipient verifies
the returned ticket with the six Recipient Verification Rules (`verify`).

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Planned files**:
- `approvals.go` — `Mint` method (context, `*wire.Error`, stable `Idempotency-Key`)
- `approvals_test.go` — route tests against `gatewaytest` fakes

**Built by**: `docs/tasks/03-client-and-routes.md`.
