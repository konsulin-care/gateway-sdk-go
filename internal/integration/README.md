# internal/integration

**Purpose**: offline end-to-end tests — enroll → signed calls → approval →
direct exchange with envelope → callback through `verify` middleware, all
against `gatewaytest` with zero network. **No build tag**: these tests run on
every `go test ./...` and on every PR (CI job `e2e-offline`).

**Allowed imports** (PRD §7 dependency rules): standard library, public SDK
packages, and `gatewaytest`.

**Related requirements**: SDK-TEST-002.

**Files** (actual):
- `doc.go` — package doc
- `routes_test.go` — `TestRouteTableRowsThroughTypedFunctions` (phase 3):
  one typed invoker per `wire.RouteTable()` row (19 invokers keyed
  `package/Method`), asserting the recorded verb/path, an
  `Idempotency-Key` on every flagged row and none elsewhere, no
  `Authorization` on public rows, and a `ks-party+jwt` bearer on party
  rows (`requireKSPartyBearer`, `pathID`, `routeFixture`)

**Planned in phase 4** (`docs/tasks/04-integration-and-release.md`):
- `enroll_test.go` — enrollment with proof of possession
- `signed_calls_test.go` — party-authenticated calls, retry/idempotency
- `exchange_test.go` — approval + direct exchange with `envelope`
- `callback_test.go` — webhook delivery through `verify` middleware
- `main_test.go` — shared offline setup

**Built by**: `docs/tasks/03-client-and-routes.md` (routes_test.go),
`docs/tasks/04-integration-and-release.md` (phase-4 suites).
