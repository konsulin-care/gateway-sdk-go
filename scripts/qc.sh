#!/usr/bin/env bash
# Quality checks for gateway-sdk-go.
#
# Usage: mise run qc [--format] [--lint] [--vet] [--lines] [--secret] [--deps]
#                    [--test] [--vuln] [--e2e-gateway]
# No flags runs all checks except --e2e-gateway (boots its own throwaway
# gateway; slow). The local gate is the CI gate: the same script runs in
# .github/workflows/pr-check.yml.
#
# Scope: auto-detects staged (lefthook pre-commit) vs all (CI / manual).
# Override with QC_SCOPE=staged|all.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

# --- Scope ---
if [ -z "${QC_SCOPE:-}" ]; then
  if [ -n "${LEFTHOOK:-}" ] || [ -n "${GIT_INDEX_FILE:-}" ]; then
    QC_SCOPE=staged
  else
    QC_SCOPE=all
  fi
fi

# --- File list ---
if [ "$QC_SCOPE" = "staged" ]; then
  # --diff-filter=d drops deleted paths so --lines/--format never stat a
  # file that the same commit removes.
  GO_FILES=$(git diff --cached --name-only --diff-filter=d -- '*.go')
else
  GO_FILES=$(find . -name '*.go' -not -path './vendor/*' -not -path './.git/*')
fi

# --- Parse flags ---
RUN_FORMAT=false; RUN_LINT=false; RUN_VET=false
RUN_LINES=false; RUN_SECRET=false; RUN_DEPS=false
RUN_TEST=false; RUN_VULN=false; RUN_E2E=false

for flag in "$@"; do
  case "$flag" in
    --format)        RUN_FORMAT=true ;;
    --lint)          RUN_LINT=true ;;
    --vet)           RUN_VET=true ;;
    --lines)         RUN_LINES=true ;;
    --secret)        RUN_SECRET=true ;;
    --deps)          RUN_DEPS=true ;;
    --test)          RUN_TEST=true ;;
    --vuln)          RUN_VULN=true ;;
    --e2e-gateway)   RUN_E2E=true ;;
    *) echo "Unknown flag: $flag"; exit 1 ;;
  esac
done

# No flags = all except --e2e-gateway
if ! $RUN_FORMAT && ! $RUN_LINT && ! $RUN_VET && ! $RUN_LINES && \
   ! $RUN_SECRET && ! $RUN_DEPS && ! $RUN_TEST && ! $RUN_VULN && ! $RUN_E2E; then
  RUN_FORMAT=true; RUN_LINT=true; RUN_VET=true; RUN_LINES=true
  RUN_SECRET=true; RUN_DEPS=true; RUN_TEST=true; RUN_VULN=true
fi

# --- Checks ---

if $RUN_FORMAT; then
  echo "==> format"
  # golangci-lint fmt --diff prints the gofmt/goimports diff and writes nothing.
  fmt_diff=$(golangci-lint fmt --diff)
  if [ -n "$fmt_diff" ]; then
    echo "$fmt_diff"
    echo "Not formatted. Run 'golangci-lint fmt' to fix."
    exit 1
  fi
fi

if $RUN_LINT; then
  echo "==> lint"
  if [ "$QC_SCOPE" = "staged" ]; then
    golangci-lint run --new-from-rev=HEAD
  else
    golangci-lint run
  fi
fi

if $RUN_VET; then
  echo "==> vet"
  go vet ./...
fi

if $RUN_LINES; then
  echo "==> max-lines"
  for f in $GO_FILES; do
    case "$f" in *_test.go) continue ;; esac
    lines=$(wc -l < "$f")
    if [ "$lines" -gt 300 ]; then
      echo "$f: $lines lines (max 300 for non-test .go files)"
      exit 1
    fi
  done
fi

if $RUN_SECRET; then
  echo "==> secrets"
  secret_re='(password|secret|pepper|private\.key)[[:space:]]*[:=]'
  if [ "$QC_SCOPE" = "staged" ]; then
    if git diff --cached --diff-filter=ACM -- '*.go' | grep -inE "$secret_re"; then
      echo "Potential secret in staged files"
      exit 1
    fi
  else
    if git diff "origin/${BASE_BRANCH:-master}...HEAD" -- '*.go' | grep -inE "$secret_re"; then
      echo "Potential secret"
      exit 1
    fi
  fi
fi

if $RUN_DEPS; then
  echo "==> deps"
  # Non-test imports only: .Imports excludes test files. Every direct import
  # of ./... must be stdlib (no dot in the first path element) or this
  # module. Fails also when go list cannot resolve an import at all.
  MODULE=$(go list -m)
  # Command substitution in an assignment propagates go list failures (e.g.
  # an unresolvable import) to set -e, so a broken import cannot pass here.
  IMPORTS=$(go list -f '{{range .Imports}}{{println .}}{{end}}' ./... | sort -u)
  BAD_IMPORTS=""
  while read -r imp; do
    [ -z "$imp" ] && continue
    case "$imp" in
      "$MODULE"|"$MODULE"/*) continue ;;   # module-internal
    esac
    case "${imp%%/*}" in
      *.*) BAD_IMPORTS="$BAD_IMPORTS $imp" ;;  # domain-like first element = third-party
    esac
  done <<< "$IMPORTS"
  if [ -n "$BAD_IMPORTS" ]; then
    echo "Non-test imports must be stdlib or $MODULE:"
    printf '  %s\n' $BAD_IMPORTS
    exit 1
  fi
fi

if $RUN_TEST; then
  echo "==> test"
  go test -race ./...
fi

if $RUN_VULN; then
  echo "==> vuln"
  govulncheck ./...
fi

if $RUN_E2E; then
  echo "==> e2e-gateway"
  bash scripts/e2e-gateway.sh
fi

echo "All checks passed"
