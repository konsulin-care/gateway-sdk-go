# identities

**Purpose**: identity routes per PRD §9.6 — `Register`
(`POST /v1/identities/register`, capability `identity:register`,
`Idempotency-Key` required), `Resolve` (`POST /v1/identities/resolve`,
capability `identity:resolve`, a read — no idempotency key),
`Link` (`POST /v1/identities/link`, capability `identity:link`,
`Idempotency-Key` required).

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Files** (actual):
- `identities.go` — `Client`, `New(cli)`, `Register`, `Resolve`, `Link`
  methods (context, `*wire.Error`)
- `doc.go` — package doc
- `identities_test.go` — route tests against `gatewaytest` fakes
  (idempotency key on creates, none on `Resolve`, `429 GW-IDX-011`
  retry)

**Built by**: `docs/tasks/03-client-and-routes.md`.
