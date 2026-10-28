# cmd/conformance

**Purpose**: command entry point for the conformance runner
(`go run ./cmd/conformance` against a live gateway, `SDK-CONF-001` …
`SDK-CONF-C01`). Thin `main.go` only: flags/env resolution and
`os.Exit(run(...))`; all case logic lives in `internal/conformance`.

**Usage**:

    conformance [-base-url url] [-operator-user user] [-callback addr] [-callback-url url] [-version]

| Flag         | Env                          | Meaning                                    |
|--------------|------------------------------|--------------------------------------------|
| `-base-url`  | `CONFORMANCE_BASE_URL`       | gateway base URL (required)                |
| `-operator-user` | `CONFORMANCE_OPERATOR_USER` | admin operator username (required)     |
| —            | `CONFORMANCE_OPERATOR_PASSWORD` | operator password (required, env only — no flag, no TOTP) |
| `-callback`  | `CONFORMANCE_CALLBACK_ADDR`  | result-callback listen `host:port` (empty binds an ephemeral loopback listener) |
| `-callback-url` | `CONFORMANCE_CALLBACK_URL` | externally reachable result-callback URL (empty uses the receiver's loopback URL) |
| `-version`   | —                            | print the runner version (Go build info, SDK-CONF-003) and exit 0 |

**Fixed-port CI wiring**: in CI the receiver binds a fixed loopback port via
`-callback`/`CONFORMANCE_CALLBACK_ADDR` (e.g. `127.0.0.1:8090`) so the port is
known ahead of time. When the target gateway runs in a container, the
callback URL it must deliver results to is the runner host's
`host.docker.internal` form of that same port, passed via
`-callback-url`/`CONFORMANCE_CALLBACK_URL` (e.g.
`http://host.docker.internal:8090/`). With no `-callback-url` the bootstrap
registers the receiver's own loopback URL — correct only when the gateway
shares the runner's network namespace.

**Exit codes** (SDK-CONF-C01): `0` green run (stdout names each executed
case), `1` any case mismatched (failing case names on stderr), `2` usage
error — a missing required value exits before any request is issued. The
operator password is never printed.

**Allowed imports** (PRD §7 dependency rules): `internal/conformance` (and
transitively the public SDK packages). Never imported by anything.

**Related requirements**: SDK-CONF-001, SDK-CONF-002, SDK-CONF-003,
SDK-CONF-C01.

**Files**:
- `main.go` — flags/env, `-version`, runner invocation, exit code
- `main_test.go` — version, usage-error, and password-redaction tests
- `README.md` — this file

**Built by**: `docs/tasks/04-integration-and-release.md`.
