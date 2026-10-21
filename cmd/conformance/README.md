# cmd/conformance

**Purpose**: command entry point for the conformance runner
(`go run ./cmd/conformance` against a live gateway, `SDK-CONF-001` …
`SDK-CONF-C01`). Thin `main.go` only: all case logic lives in
`internal/conformance`. Until the runner is built it prints
`not implemented` to stderr and exits 1.

**Allowed imports** (PRD §7 dependency rules): `internal/conformance` (and
transitively the public SDK packages). Never imported by anything.

**Related requirements**: SDK-CONF-001, SDK-CONF-002, SDK-CONF-003,
SDK-CONF-C01.

**Planned files**:
- `main.go` — flags, runner invocation, exit code (exists as stub)
- `README.md` — this file

**Built by**: `docs/tasks/04-integration-and-release.md`.
