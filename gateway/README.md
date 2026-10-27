# gateway

**Purpose**: gateway-level public routes — `JWKS` (`GET /.well-known/jwks`) and
`Health` (`GET /health`) per PRD §9.6. Thin typed wrappers over the client
core.

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Files** (actual):
- `gateway.go` — `Client`, `New(cli)`, `JWKS`, `Health` methods
  (context support, `*wire.Error`)
- `doc.go` — package doc
- `gateway_test.go` — route tests against `gatewaytest` fakes (public
  rows send no `Authorization`; non-2xx surfaces `*wire.Error`)

**Built by**: `docs/tasks/03-client-and-routes.md`.
