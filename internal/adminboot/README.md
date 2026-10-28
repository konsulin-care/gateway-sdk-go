# internal/adminboot

**Purpose**: minimal admin bootstrap for the conformance runner's setup only —
admin login (`POST /v1/admin/auth/login`), party creation
(`POST /v1/admin/parties`), enrollment tokens
(`POST /v1/admin/parties/{id}/enrollment-token`), capability grants
(`POST .../capabilities`) and revokes (`DELETE .../capabilities/{capability}`),
party revokes (`POST .../revoke`), and tier changes
(`POST .../tier` — e.g. promoting an enrolled party to `konsulin`).
Internal by design and never part of the public client (PRD §5: no admin
routes in the public surface).

**Allowed imports** (PRD §7 dependency rules): standard library, `wire`.

**Related requirements**: SDK-CONF-001.

**Files** (actual):
- `doc.go` — package doc
- `login.go` — admin session login
- `parties.go` — party creation and enrollment-token issuance
- `capabilities.go` — capability grants and revokes, party revokes
- `tier.go` — `SetTier` party tier changes
- `adminboot_test.go` — against `gatewaytest` fakes

**Built by**: `docs/tasks/04-integration-and-release.md`.
