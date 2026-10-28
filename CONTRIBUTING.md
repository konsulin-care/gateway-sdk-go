# Contributing to gateway-sdk-go

Thanks for contributing. This repo is the public, stdlib-only Go client and
verifier for the Konsulin gateway. [AGENTS.md](AGENTS.md) is the working
convention set — contract authority, dependency rules, security invariants,
boundaries; this file is the pull-request workflow on top of it.

## Before you start

- Contract authority resolves upward: the gateway's Bruno collections plus
  its normative sections > the mirrored golden vectors in
  [testdata/golden/](testdata/golden/) > the PRD
  [PROPOSAL.md](PROPOSAL.md). This repo never redefines wire format, and no
  test may read a path outside this module.
- Ask first (AGENTS.md "Boundaries"): new dependencies (even test-only),
  public API or wire-shape changes, work outside the declared contract
  files, touching `LICENSE` or `debates/`.

## Sign off your commits (DCO)

Every commit must carry a `Signed-off-by:` line matching its author,
certifying the [Developer Certificate of Origin, Version 1.1](https://developercertificate.org/):

```sh
git commit -s   # appends "Signed-off-by: Your Name <you@example.com>"
```

The `DCO` workflow ([.github/workflows/dco.yml](.github/workflows/dco.yml))
checks every commit in the pull request and fails, naming each commit that
lacks the line. There is no override and no history rewrite — to fix an
unsigned commit, amend it and force-push:

```sh
git commit --amend -s --no-edit && git push --force-with-lease
# several commits:
git rebase master --exec 'git commit --amend --no-edit -s'
```

## Test-driven development

- Every `SDK-*` behavior starts with its named failing test (red), then the
  minimal implementation (green); the test ships in the same commit as the
  change. Tests are the specification — never delete, skip, or weaken one to
  land a commit.
- `github.com/stretchr/testify`: `require` for setup, `assert` for outcomes.
- Offline only: `httptest` + fixtures, zero network. Tests read in-module
  paths only (`testdata/`, fixtures, `testdata/golden/MANIFEST.json`).

## Quality gate

```sh
mise install      # pins Go, golangci-lint, lefthook, govulncheck
mise run hooks    # install the lefthook pre-commit/pre-push hooks
mise run qc       # format, lint, vet, lines, secret, deps, test, vuln
```

The local gate is the CI gate — both run [scripts/qc.sh](scripts/qc.sh).
lefthook pre-commit runs format, staged-scope lint, vet, the 300-line cap
and the secret scan on every commit; pre-push runs the full lint, deps,
`go test -race ./...`, and govulncheck. Never `git commit --no-verify` on a
commit that touches `.go` files — fix the failing check instead.

## Style

- Files ≤ 300 lines (split packages, never truncate); function complexity
  ≤ 15; a doc comment on every exported symbol.
- Conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`, `chore:`),
  subject < 75 characters, describing what and why.

## Releases and compatibility

- Semver v0.x (ADR-009): minors may break, never silently — every break
  carries a [CHANGELOG.md](CHANGELOG.md) entry and a
  [COMPATIBILITY.md](COMPATIBILITY.md) update **in the same PR**.
- No tag without green CI + green conformance.

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md) — never in a public
issue or pull request.
