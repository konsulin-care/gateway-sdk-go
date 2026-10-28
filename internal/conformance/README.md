# internal/conformance

**Purpose**: the shared conformance cases executed by `cmd/conformance` against
a live gateway. The positive QC chain runs gateway health, admin bootstrap
(login, create party, issue the enrollment token — no capability grants),
enrollment (registers the party key and promotes the party to the konsulin
tier over a fresh admin login), then rotation, JWKS, identities, approvals,
listings, payments, webhooks, and the result callback. The negative cases
follow in destructive-last order: wrong signing key, replayed enrollment
token, wrong/missing `typ`, `body_sha256` mismatch, expired token, unknown
`kid` after one refetch, idempotency replay, missing capability
(`capability_denied`, after the `webhook:invoke` revoke), and revoked party
last — the party revoke ends the run.

**Allowed imports** (PRD §7 dependency rules): standard library and public SDK
packages (plus `internal/adminboot` for setup).

**Related requirements**: SDK-CONF-001, SDK-CONF-002, SDK-CONF-003,
SDK-CONF-C01.

**Runner**: `Run` executes the registry, prints one result line per case to
stdout, prints failing case names to stderr, and returns the exit code
(`ExitOK`/`ExitMismatch`/`ExitUsage` — usage errors are detected before any
request). `Version` reports the runner version from the Go build info
(SDK-CONF-003). The operator password comes from `Config.OperatorPass`
(environment only, no flag) and is never printed. The runner threads
`Config.CallbackURL` and `Config.PartyHealthURL` into the case `Env` (the
bootstrap registers them as `endpoints.callbacks` and `endpoints.health`); an
unset `Config.CallbackURL` falls back to the result-callback receiver's own
loopback URL. The receiver binds `Config.CallbackAddr` (empty selects an
ephemeral loopback listener) — in fixed-port CI wiring the receiver takes a
fixed loopback port via `CallbackAddr` while the externally reachable URL is
the runner host's `host.docker.internal` form of that port.

**Files**:
- `registry.go` — ordered case registry (Kind, Case, Env, `Registry()`)
- `positive.go` — QC-chain happy paths (SDK-CONF-001)
- `negative.go` — SDK-CONF-002 deny cases
- `callback.go` — plain-HTTP result-callback receiver
- `runner.go` — registry execution, report streams, exit codes (SDK-CONF-C01)
- `config.go` — runner configuration and validation (usage errors)
- `version.go` — runner version from runtime/debug build info (SDK-CONF-003)
- `doc.go` — package doc plus the shared case helpers (client builders, probes)
- `conformance_test.go` — QC-chain registry and import tests
- `cases_test.go` — negative-case and callback-receiver tests
- `runner_test.go` — runner exit codes, usage errors, password redaction

**Built by**: `docs/tasks/04-integration-and-release.md`.
