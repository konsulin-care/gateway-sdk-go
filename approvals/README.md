# approvals

**Purpose**: approval ticket routes per PRD §9.6 — `Mint`
(`POST /v1/approvals`) with capability `approval:referral` or
`approval:export:<study>`, `Idempotency-Key` required. The recipient verifies
the returned ticket with the six Recipient Verification Rules (`verify`).

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Files** (actual):
- `approvals.go` — `Client`, `New(cli)`, `Mint` method (context,
  `*wire.Error`, stable `Idempotency-Key`)
- `doc.go` — package doc
- `approvals_test.go` — route tests against `gatewaytest` fakes;
  `capability_denied` surfaces as `*wire.Error` after one attempt

**Built by**: `docs/tasks/03-client-and-routes.md`.
