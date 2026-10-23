# gatewaytest

**Purpose**: the offline test kit — `testdata/golden` fixture loaders,
`MANIFEST.json` verification (fail closed on a hash mismatch, missing entry,
or an unlisted vector — offline, no sibling gateway checkout), fake
gateway servers on `httptest`, a token minter with a generated test key,
and a deterministic `ReplayCache`. Tests using it run with zero network and
read no path outside the module. Nothing except tests and
`cmd/conformance` may import this package.

**Allowed imports** (PRD §7 dependency rules): standard library and public SDK
packages (including `internal/*` where a fake must mint real tokens).

**Related requirements**: SDK-TEST-001, SDK-TEST-002.

**Planned files**:
- `fixtures.go` — golden-vector fixture loader
- `manifest.go` — `MANIFEST.json` loader/verifier (fail closed, ADR-004)
- `server.go` — fake gateway `httptest` server
- `minter.go` — token minter with a generated test key
- `replay.go` — deterministic `ReplayCache`
- extended in phase 3: fake handlers per §9.6 route
- tests split per unit: `golden_test.go`, `fixtures_test.go`,
  `jwksserver_test.go`, `minter_test.go`, `replay_test.go`,
  `manifest_test.go` (each ≤ 300 lines)

**Built by**: `docs/tasks/01-foundation-test-kit.md` (v1), extended in
`docs/tasks/03-client-and-routes.md`.
