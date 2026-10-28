# gatewaytest

**Purpose**: the offline test kit — `testdata/golden` fixture loaders,
`MANIFEST.json` verification (fail closed on a hash mismatch, missing entry,
or an unlisted vector — offline, no sibling gateway checkout), fake
gateway servers on `httptest`, a token minter with a generated test key,
a deterministic `ReplayCache`, and the fake handler set for every §9.6
route (canned responses, idempotency replay, scripted 409/429/5xx
sequences, request recording) plus opt-in admin fakes with the Bruno
admin-collection shapes (off by default: admin paths stay 404 until
enabled). Tests using it run with zero network and
read no path outside the module. Nothing except tests and
`cmd/conformance` may import this package.

**Allowed imports** (PRD §7 dependency rules): standard library and public SDK
packages (including `internal/*` where a fake must mint real tokens).

**Related requirements**: SDK-TEST-001, SDK-TEST-002.

**Files** (actual):
- `doc.go` — package doc
- `fixtures.go` — `Fixture`, `LoadFixtures` golden-vector loader
- `manifest.go` — `Manifest`, `LoadManifest`, `VerifyManifest`
  (fail closed, ADR-004; `ErrManifest*` sentinels)
- `server.go` — `JWKSServer`, `NewJWKSServer`, `Ed25519JWKS` fake JWKS
  `httptest` server
- `minter.go` — `Minter`, `NewMinter`, `MintES256` token minter with a
  generated test key
- `replay.go` — `ReplayCache`, `NewReplayCache` deterministic cache;
  satisfies `verify.ReplayCache` (asserted in `replay_test.go`, so
  non-test `gatewaytest` never imports `verify`)
- `handlers.go` — `Gateway`, `NewGateway`, `URL`, `Close`, `Recorded`,
  `RecordedRequest` (verb, path, auth, idempotency key, party jti)
- `handlers_admin.go` — `AdminOptions`, `EnableAdmin` opt-in canned
  admin handlers (login username/password-only, create party, issue
  enrollment token, grant and revoke capability, revoke party, set
  party tier; Bruno shapes, admin Bearer 401s; admin paths stay 404
  unless enabled)
- `handlers_routes.go` — one canned handler per §9.6 route row
- `handlers_idempotency.go` — per-key idempotency store: reserve,
  replay a stored 2xx, release on non-2xx
- `handlers_jti.go` — `EnforceSingleUsePartyJTI` opt-in single-use
  party jti enforcement: an already-seen bearer jti on a §9.6 route
  answers 401 GW-ADMIN-004 (checked after scripted steps, before the
  idempotency store; off by default, admin fakes unaffected)
- `handlers_script.go` — `ScriptStep`, `Gate`, `Script`, `Block`
  (scripted sequences and request gates for retry tests)
- tests split per unit: `golden_test.go`, `fixtures_test.go`,
  `jwksserver_test.go`, `minter_test.go`, `replay_test.go`,
  `manifest_test.go`, `handlers_test.go`, `handlers_admin_test.go`,
  `handlers_jti_test.go`
  (each ≤ 300 lines)

**Built by**: `docs/tasks/01-foundation-test-kit.md` (v1), extended in
`docs/tasks/03-client-and-routes.md` (route handlers, idempotency and
scripted-sequence fakes — SDK-TEST-001).
