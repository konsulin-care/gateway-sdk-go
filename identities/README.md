# identities

**Purpose**: identity routes per PRD §9.6 — `Register`
(`POST /v1/identities/register`, capability `identity:register`), `Resolve`
(`POST /v1/identities/resolve`, capability `identity:resolve`), `Link`
(`POST /v1/identities/link`, capability `identity:link`).

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Planned files**:
- `identities.go` — `Register`, `Resolve`, `Link` methods (context, `*wire.Error`)
- `identities_test.go` — route tests against `gatewaytest` fakes

**Built by**: `docs/tasks/03-client-and-routes.md`.
