# ADR 010: Tooling — mise, lefthook, golangci-lint v2

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

The SDK needs one reproducible toolchain for local dev and CI, a quality gate
that runs identically in both, and repo-hygiene rules (complexity, file size)
that are enforced rather than suggested. The repo is solo-maintained at
bootstrap; contributor mechanics like DCO only matter once external PRs
arrive.

## Decision

- **mise** pins every tool (`.mise.toml`): Go 1.27, golangci-lint 2.15.0,
  lefthook 2.2.2, govulncheck (version-pinned). Tasks: `mise run qc`,
  `mise run hooks`, `mise run e2e-gateway`.
- **lefthook** guards the repo, **pre-commit and pre-push hooks only** —
  no `commit-msg` hook, no `pre-merge-commit` hook:
  - pre-commit (parallel): format, lint (staged, `--new-from-rev=HEAD`), vet,
    lines, secret — all via `mise run qc --<flag>`.
  - pre-push: full lint (`QC_SCOPE=all`), deps, `go test -race ./...`, vuln.
  - The local gate is the CI gate: both run the same `scripts/qc.sh`.
- **golangci-lint v2** (`.golangci.yml`): errcheck, govet, ineffassign,
  staticcheck, unused, revive (exported-symbol doc comments), depguard
  (non-test files: stdlib + this module only; denies go-jose, x/crypto,
  jwx — ADR-002); formatters gofmt + goimports.
- **Complexity**: gocyclo and gocognit with **min-complexity 15 — a function
  of complexity 15 passes, 16 is rejected**; `_test.go` excluded from both.
- **File size**: non-test `.go` files capped at **300 lines** (`qc --lines`);
  split packages, never truncate.
- **CI jobs** (`.github/workflows/pr-check.yml`): `quality` (full qc),
  `e2e-offline` (`go test -race ./internal/integration/...`, required),
  `e2e-gateway` (pinned private ghcr image, skipped for fork PRs, skipped
  counts as passing), `actionlint`.
- **DCO is deferred**: no DCO check and no sign-off enforcement at bootstrap.
  It becomes required **from the first external contribution**, enforced in CI
  at that point (phase 4 enables it before the first external PR); commits
  already carry conventional subjects (< 75 chars).

## Consequences

**Positive:**
- `mise install` + `mise run hooks` reproduces the exact CI toolchain;
  no version drift between laptop and pipeline.
- Bypass policy is explicit: never `--no-verify` on commits touching `.go`
  (AGENTS.md) — fix the failing check instead of skipping the gate.
- Complexity and size limits are mechanical; gocognit catches deeply nested
  code gocyclo misses.

**Negative:**
- The 15 threshold admits moderately complex functions that a stricter gate
  (e.g., 10) would force apart — accepted for a small-team codebase; split
  before growing.
- No DCO until the first external PR means sign-off history is incomplete —
  accepted while the repo is single-author; enabling it later is a CI change,
  not a history rewrite.
