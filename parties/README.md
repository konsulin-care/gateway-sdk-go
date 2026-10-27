# parties

**Purpose**: party lifecycle routes per PRD §9.6 — `Enroll`
(`POST /v1/parties/{id}/enroll`, enrollment token + proof of possession,
Ed25519 by default) and `EnrollES256` (same route, ES256 opt-in),
`Rotate` (`POST /v1/parties/{id}/keys`, signed by the party's **current
active key only** — a superseded grace-window key is rejected with
`GW-PARTY-011`), `JWKS` (`GET /v1/parties/{id}/jwks`), `Health`
(`GET /v1/parties/{id}/health`).

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002 (plus SDK-AUTH-002 for the
enrollment PoP built by `auth`).

**Files** (actual):
- `parties.go` — `Client`, `New(cli, gatewayURL)` (absolute gateway URL
  for the enrollment requests), `Rotate`, `JWKS`, `Health` methods
  (context, `*wire.Error`)
- `enroll.go` — `EnrollInput`, `Enroll`, `EnrollES256` with the
  proof-of-possession body, `Idempotency-Key` on the create, and the
  enrollment's own `Retry-After`-honouring attempt loop (fresh `jti`
  per attempt)
- `doc.go` — package doc
- `parties_test.go` — route tests against `gatewaytest` fakes,
  `Idempotency-Key` on creates, `GW-PARTY-011` after one attempt

**Built by**: `docs/tasks/03-client-and-routes.md`.
