# internal/integration

**Purpose**: offline end-to-end tests — enroll → signed calls → approval →
direct exchange with envelope → callback through `verify` middleware, all
against `gatewaytest` with zero network. **No build tag**: these tests run on
every `go test ./...` and on every PR (CI job `e2e-offline`).

**Allowed imports** (PRD §7 dependency rules): standard library, public SDK
packages, and `gatewaytest`.

**Related requirements**: SDK-TEST-002, SDK-README-001.

**Files** (actual):
- `doc.go` — package doc
- `main_test.go` — `TestMain` (transport guard refusing non-loopback
  dials, probed by `TestMainInstallsLoopbackOnlyDial`), the shared
  `fixture` (gatewaytest server, minter + JWKS, deterministic
  `ReplayCache`, verifier, party client) and
  `TestIntegrationFlowsOffline` (enroll → signed-calls → exchange →
  callback as subtests)
- `enroll_test.go` — `runEnrollFlow`: RFC 7638 kid, PoP `body_sha256`
  over the exact POST bytes, `parties.Enroll` success
- `signed_calls_test.go` — `runSignedCallsFlow`: distinct jti per
  attempt, 409→200 reuses one Idempotency-Key, new key only after a
  terminal 402 (ADR-011)
- `exchange_test.go` — `runExchangeFlow`: `approvals.Mint` ticket passes
  the recipient's six-rule check; `envelope.Seal` → `Open` byte-identical
- `callback_test.go` — `runCallbackFlow`: delivery through `verify`
  middleware, `webhook_id` duplicate rejection, payment-required and
  service-receipt `ks-event+jwt` acceptance
- `routes_test.go` — `TestRouteTableRowsThroughTypedFunctions` (phase 3):
  one typed invoker per `wire.RouteTable()` row (19 invokers keyed
  `package/Method`), asserting the recorded verb/path, an
  `Idempotency-Key` on every flagged row and none elsewhere, no
  `Authorization` on public rows, and a `ks-party+jwt` bearer on party
  rows (`requireKSPartyBearer`, `pathID`, `routeFixture`)
- `readme_test.go` — `TestReadmeRecipesMatchPublicAPI` (SDK-README-001):
  extracts the five tagged Go recipe blocks from the root `README.md`
  (enrollment, signed-calls, callback, exchange, pepper) and asserts each
  matches its `Example_*` body after whitespace normalization; the pepper
  block must open the sealed JWE via `envelope.Open` and write nothing to
  disk or env. Holds the five offline `Example_*` recipes themselves
  (runnable via `go test -run Example`).

**Built by**: `docs/tasks/03-client-and-routes.md` (routes_test.go),
`docs/tasks/04-integration-and-release.md` (SDK-TEST-002: main, enroll,
signed_calls, exchange, callback; SDK-README-001: readme_test.go).
