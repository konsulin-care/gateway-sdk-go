# gatewaytest

**Purpose**: the offline test kit — `testdata/golden` fixture loaders, fake
gateway servers on `httptest`, a token minter with a generated test key, and a
deterministic `ReplayCache`. Tests using it run with zero network. Nothing
except tests and `cmd/conformance` may import this package.

**Allowed imports** (PRD §7 dependency rules): standard library and public SDK
packages (including `internal/*` where a fake must mint real tokens).

**Related requirements**: SDK-TEST-001, SDK-TEST-002.

**Planned files**:
- `fixtures.go` — golden-vector fixture loader
- `server.go` — fake gateway `httptest` server
- `minter.go` — token minter with a generated test key
- `replay.go` — deterministic `ReplayCache`
- extended in phase 3: fake handlers per §9.6 route

**Built by**: `docs/tasks/01-foundation-test-kit.md` (v1), extended in
`docs/tasks/03-client-and-routes.md`.
