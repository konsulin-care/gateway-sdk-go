# wire

**Purpose**: the shared wire contract — request/response DTOs for every route,
the six `typ` constants, the seven token purposes (incl. the hardening-era
`payment-required` / `service-receipt`), the capability catalog, the
token-kind table (required vs conditional claims), `*wire.Error`, the
`GW-*` error catalog as data (`codes.go`), and retry classification
(`retry.go`) derived from catalog dispositions.

**Allowed imports** (PRD §7 dependency rules): standard library only — nothing
else in the module, nothing outside it.

**Related requirements**: SDK-WIRE-001..004; consumed by
SDK-CLIENT-003, SDK-RETRY-002/003 (classification), and SDK-API-001.

**Planned files**:
- `constants.go` — `typ` constants, token purposes, capability catalog, token-kind table (required/conditional split)
- `errors.go` — `*Error{Code, Message, RequestID, Status}` and sentinels
- `codes.go` — the full `GW-*` catalog as data: code, HTTP status, disposition (`LookupCode`, `Codes`)
- `retry.go` — `Retryable` / `RequiresNewIdempotencyKey` classification from the catalog (ADR-011, ADR-012)
- `dto_parties.go`, `dto_identities.go`, `dto_approvals.go`, `dto_listings.go`,
  `dto_payments.go`, `dto_webhooks.go` — route DTOs, JSON tags byte-matching the Bruno examples
- `*_test.go` — catalog and DTO shape tests

**Built by**: `docs/tasks/01-foundation-test-kit.md` (typ/purpose/capability
constants, `*wire.Error`, error catalog); DTOs extended in
`docs/tasks/03-client-and-routes.md`.
