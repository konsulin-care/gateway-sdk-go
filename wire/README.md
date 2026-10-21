# wire

**Purpose**: the shared wire contract — request/response DTOs for every route,
the six `typ` constants, token purposes, the capability catalog, the
token-kind table, and `*wire.Error`, the one error type surfaced by every SDK
call.

**Allowed imports** (PRD §7 dependency rules): standard library only — nothing
else in the module, nothing outside it.

**Related requirements**: SDK-WIRE-001, SDK-WIRE-002, SDK-WIRE-003; consumed by
SDK-CLIENT-003 and SDK-API-001.

**Planned files**:
- `constants.go` — `typ` constants, token purposes, capability catalog, token-kind table
- `errors.go` — `*Error{Code, Message, RequestID, Status}` and the known error catalog
- `dto_parties.go`, `dto_identities.go`, `dto_approvals.go`, `dto_listings.go`,
  `dto_payments.go`, `dto_webhooks.go` — route DTOs, JSON tags byte-matching the Bruno examples
- `*_test.go` — catalog and DTO shape tests

**Built by**: `docs/tasks/01-foundation-test-kit.md` (typ/purpose/capability
constants, `*wire.Error`, error catalog); DTOs extended in
`docs/tasks/03-client-and-routes.md`.
