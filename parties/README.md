# parties

**Purpose**: party lifecycle routes per PRD §9.6 — `Enroll`
(`POST /v1/parties/{id}/enroll`, enrollment token + proof of possession),
`Rotate` (`POST /v1/parties/{id}/keys`), `JWKS`
(`GET /v1/parties/{id}/jwks`), `Health` (`GET /v1/parties/{id}/health`).

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002 (plus SDK-AUTH-002 for the
enrollment PoP built by `auth`).

**Planned files**:
- `parties.go` — `Enroll`, `Rotate`, `JWKS`, `Health` methods (context, `*wire.Error`)
- `parties_test.go` — route tests against `gatewaytest` fakes, `Idempotency-Key` on creates

**Built by**: `docs/tasks/03-client-and-routes.md`.
