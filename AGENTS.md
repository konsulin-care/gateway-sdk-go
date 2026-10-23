# AGENTS.md

## What this is

The Gateway SDK for Go (`github.com/konsulin-care/gateway-sdk-go`) is the public,
stdlib-only Go client and verifier for the Konsulin gateway: enrollment and key
rotation, identity, approvals, listings, payments, webhooks, inbound callback
verification, and the JWE envelope. MIT, pre-v0.1.0.

- PRD: [PROPOSAL.md](PROPOSAL.md) (every `SDK-*` requirement) · stub: [README.md](README.md).

## Contract authority (conflicts resolve upward)

1. Gateway Bruno collections (`../gateway/docs/api/`) plus the gateway's
   normative sections: Token Kinds, Recipient Verification Rules, JWE Envelope,
   Gateway Key Rotation.
2. Mirrored golden vectors in `testdata/golden/`.
3. The PRD. It never redefines wire format.

The gateway checkout is an **authoring-time reference only**: contract facts
are read from it while writing code and docs, and `scripts/mirror-golden.sh`
reads it to refresh the mirror. **No test may read a path outside this
module** — golden-vector integrity is proven against the in-repo
`testdata/golden/MANIFEST.json` (ADR-004), and gateway drift is the
out-of-band local check `mise run qc --mirror-check`, never a CI gate.

## Commands

- `mise install` then `mise run hooks` — toolchain + lefthook pre-commit/pre-push.
- `mise run qc [--format --lint --vet --lines --secret --deps --test --vuln]`
  — quality gate; no flags runs everything except `--e2e-gateway`.
- `go test ./...` — offline unit tests, zero network.

## Navigation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · [docs/ADR/](docs/ADR/) · [docs/tasks/](docs/tasks/)
- [README.md](README.md) (root stub) · [testdata/golden/README.md](testdata/golden/README.md) — one README per package dir below:

- [wire](wire/README.md)
- [auth](auth/README.md)
- [client](client/README.md)
- [verify](verify/README.md)
- [identity](identity/README.md)
- [envelope](envelope/README.md)
- [gateway](gateway/README.md)
- [parties](parties/README.md)
- [identities](identities/README.md)
- [approvals](approvals/README.md)
- [listings](listings/README.md)
- [payments](payments/README.md)
- [webhooks](webhooks/README.md)
- [gatewaytest](gatewaytest/README.md)
- [internal/jws](internal/jws/README.md)
- [internal/jwk](internal/jwk/README.md)
- [internal/adminboot](internal/adminboot/README.md)
- [internal/conformance](internal/conformance/README.md)
- [internal/integration](internal/integration/README.md)
- [cmd/conformance](cmd/conformance/README.md)

## Dependency rules (summary)

- Non-test code imports stdlib or this module only; test-only deps (testify)
  are allowed. `wire`, `internal/jws`, `internal/jwk` are stdlib-only;
  `internal/*` never re-exported; no go-jose, x/crypto, or lestrrat jwx.
  Import table: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security invariants

- Stdlib-only runtime; no third-party imports from non-test code.
- Fail closed: any signature, `typ`, claim, audience, expiry, `body_sha256`, or
  envelope failure denies — never a partial accept.
- Exact `typ` per Token Kinds row; missing/generic `typ` fails even under a valid signature.
- Kid-only key selection from JWKS only: one rate-limited refetch per unknown
  `kid`, then deny.
- Never log secrets, bodies, tokens, keys, or the pepper.
- Key custody stays with the caller: the SDK never generates, stores, or rotates production keys.

## Boundaries

Always: TDD (failing test first) · testify `require`/`assert` · offline tests ·
doc comment on every exported symbol · `mise run qc` green before hand-off.

Ask first: new dependencies (even test-only), public API or wire-shape changes,
work outside the declared contract files, touching `LICENSE` or `debates/`.

Never: `--no-verify` on commits touching `.go` · third-party runtime imports ·
local edits to golden vectors · mirroring the gateway signing key · admin routes
in the public client · secrets or keys in logs or commits.

## Hook bypass policy

Never use `git commit --no-verify` on a commit that touches `.go` files — fix
the failing check instead; lefthook pre-commit/pre-push is the gate.

## Testing

- TDD: write the failing test first for every `SDK-*` behavior.
- `github.com/stretchr/testify`: `require` for setup, `assert` for outcomes.
- Unit tests are offline (`httptest` + fixtures, zero network) and `-race` clean.
- Tests read only in-module paths (`testdata/`, fixtures, `testdata/golden/MANIFEST.json`);
  no test may open `../gateway` or any other path outside the module.

## Conventions

- Files ≤ 300 lines — split packages, never truncate.
- Doc comment on every exported symbol (purpose, parameters, return value).
- Conventional commits, subject < 75 chars.
- Complexity ≤ 15 (gocyclo/gocognit: 15 passes, >15 rejected).
