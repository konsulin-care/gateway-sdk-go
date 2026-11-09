# wire

**Purpose**: the shared wire contract — request/response DTOs for every route,
the six `typ` constants, the seven token purposes (incl. the hardening-era
`payment-required` / `service-receipt`), the capability catalog, the
token-kind table (required vs conditional claims), `*wire.Error`, the
`GW-*` error catalog as data (`codes.go`), retry classification
(`retry.go`) derived from catalog dispositions, and the normative §9.6
route table (`routes.go`). It also carries the shared replay-dedupe
contract (`ReplayCache` interface with the `ScopeJTI`, `ScopeWebhookID`,
`ScopeNonce` scopes), the settlement callback body
(`SettlementNotification` with `SettlementStatusPaid`/`Expired`/`Canceled`),
external-id parsing (`ParseExternalID`, `ErrInvalidExternalID`), and the
webhook delivery body (`DeliveryBody` with `ContentTypeJOSE` =
`application/jose`).

**Allowed imports** (PRD §7 dependency rules): standard library only — nothing
else in the module, nothing outside it.

**Related requirements**: SDK-WIRE-001..004; consumed by
SDK-CLIENT-003, SDK-RETRY-002/003 (classification), and SDK-API-001.

**Files** (actual):
- `constants.go` — `typ` constants, token purposes, capability catalog,
  token-kind table (`Typs`, `Purposes`, `CapabilityCatalog`,
  `TokenKindTable`, `KindForTyp` — deep-copying, SDK-WIRE-002)
- `errors.go` — `*Error{Code, Message, RequestID, Status}`, sentinels,
  `DecodeError(status, body)` (SDK-WIRE-003)
- `codes.go` — the full `GW-*` catalog as data: `Disposition`,
  `CodeEntry{Code, HTTPStatus, Disposition, Endpoints}`, `LookupCode`,
  `Codes` (SDK-WIRE-003)
- `retry.go` — `Retryable` / `RequiresNewIdempotencyKey` classification
  from the catalog (ADR-011, ADR-012; SDK-RETRY-002/003)
- `routes.go` — `AuthClass`, `Route`, `RouteTable()`: the normative §9.6
  route table, the 19 party-facing rows with verb, path, auth class and
  idempotency flag (SDK-API-001)
- `replay.go` — `ReplayCache` interface (`Check`/`Release`, deny on error)
  and the `ScopeJTI`, `ScopeWebhookID`, `ScopeNonce` scope constants
- `external_id.go` — `ParseExternalID` (party:domain:opaque) and
  `ErrInvalidExternalID`
- `dto_settlement.go` — `SettlementNotification` and the
  `SettlementStatusPaid`/`SettlementStatusExpired`/`SettlementStatusCanceled`
  status constants
- `dto_delivery.go` — `DeliveryBody` (`envelope`, `result_ticket`) and
  `ContentTypeJOSE` (`application/jose`)
- `dto_parties.go`, `dto_identities.go`, `dto_approvals.go`,
  `dto_listings.go`, `dto_payments.go`, `dto_webhooks.go` — route DTOs,
  JSON tags byte-matching the Bruno examples (SDK-WIRE-001), incl.
  `ServiceReceiptBody` and the `listings.List` row shape
- `doc.go` — package doc
- `testdata/bruno-examples.json` — one mirrored Bruno example body per
  route DTO (in-module mirror only; tests never read `../gateway`, ADR-004)
- tests: `constants_test.go`, `errors_test.go` (catalog, sentinels,
  classification, fuzz), `dto_test.go` (Bruno round-trip, required keys,
  unknown-field decode), `routes_test.go` (table shape/exclusions/fresh
  copy), `replay_test.go` (scopes, shared cache), `external_id_test.go`,
  `dto_settlement_test.go`, `dto_delivery_test.go`,
  `dto_payments_return_test.go`

**Built by**: `docs/tasks/01-foundation-test-kit.md` (typ/purpose/capability
constants, `*wire.Error`, error catalog); DTOs, route table and tests
extended in `docs/tasks/03-client-and-routes.md`.
