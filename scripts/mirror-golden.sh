#!/usr/bin/env bash
# Mirror the PRD §11 golden vectors from the local gateway checkout into
# testdata/golden/, then regenerate MANIFEST.json with fresh per-file
# SHA-256 hashes and the gateway commit the vectors came from.
#
# Usage: scripts/mirror-golden.sh [--check] [gateway-golden-dir]
#   (default)   copy the allow-listed files and rewrite MANIFEST.json
#   --check     local-only drift check: compare the mirror against the
#               gateway checkout byte-for-byte; skipped (exit 0) when the
#               checkout is absent. Never runs in CI.
# Default source: ../gateway/testdata/golden (sibling checkout).
#
# Copies an explicit allow-list of the 12 mirrored files, one cp per file —
# never a glob, never a directory copy. The gateway signing key
# (testonly-gateway-signing-private.key) is never mirrored: a stray copy in
# the destination fails the check and is removed by the mirror run.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DST="$REPO_ROOT/testdata/golden"

# Explicit allow-list — the 12 PRD §11 mirrored files. Never derive this
# from a directory listing.
FILES=(
  gateway-jwks.json
  ks-access.json
  ks-approval.json
  ks-delivery.json
  ks-event-service-result.json
  ks-party.json
  ks-result.json
  settlement-expired-buyer.json
  settlement-expired-provider.json
  settlement-paid-buyer.json
  settlement-paid-provider.json
  testonly-party-private.key
)

signing_key="testonly-gateway-signing-private.key"

MODE=mirror
if [ "${1:-}" = "--check" ]; then
  MODE=check
  shift
fi
SRC="${1:-$REPO_ROOT/../gateway/testdata/golden}"

# sha256_file prints the lowercase hex SHA-256 of the file at $1.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# source_commit prints the full git commit of the checkout containing $1.
source_commit() {
  local commit
  if ! commit=$(git -C "$1" rev-parse HEAD 2>/dev/null); then
    echo "mirror-golden: source is not inside a git checkout: $1" >&2
    return 1
  fi
  if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "mirror-golden: unexpected git commit: $commit" >&2
    return 1
  fi
  printf '%s\n' "$commit"
}

if [ "$MODE" = "check" ]; then
  # Local-only drift check: skipped, never failed, without the checkout.
  if [ ! -d "$SRC" ]; then
    echo "mirror-check: skipped — no gateway checkout at $SRC"
    exit 0
  fi
  drift=()
  for f in "${FILES[@]}"; do
    if [ ! -f "$SRC/$f" ]; then
      echo "mirror-check: missing source file: $SRC/$f" >&2
      exit 1
    fi
    if [ ! -f "$DST/$f" ] || ! cmp -s "$SRC/$f" "$DST/$f"; then
      drift+=("$f")
    fi
  done
  if [ -e "$DST/$signing_key" ]; then
    echo "mirror-check: $signing_key must never be mirrored — found in $DST" >&2
    exit 1
  fi
  if [ "${#drift[@]}" -gt 0 ]; then
    echo "mirror-check: drift between $SRC and $DST:" >&2
    printf '  %s\n' "${drift[@]}" >&2
    echo "mirror-check: re-run scripts/mirror-golden.sh" >&2
    exit 1
  fi
  echo "mirror-check: ${#FILES[@]} files match $SRC"
  exit 0
fi

if [ ! -d "$SRC" ]; then
  echo "mirror-golden: source directory not found: $SRC" >&2
  exit 1
fi

# Provenance: the manifest records exactly which gateway commit the
# copied bytes came from, so drift detection can be out-of-band.
COMMIT=$(source_commit "$SRC")

mkdir -p "$DST"

for f in "${FILES[@]}"; do
  if [ ! -f "$SRC/$f" ]; then
    echo "mirror-golden: missing source file: $SRC/$f" >&2
    exit 1
  fi
  cp "$SRC/$f" "$DST/$f"
  echo "mirrored $f"
done

# The gateway signing key is never mirrored; remove any stray copy.
if [ -e "$DST/$signing_key" ]; then
  rm "$DST/$signing_key"
  echo "mirror-golden: removed stray $signing_key from $DST" >&2
fi

# Rewrite MANIFEST.json: gateway commit plus one SHA-256 per allow-listed
# file, hashed over the exact mirrored bytes in the destination.
MANIFEST="$DST/MANIFEST.json"
{
  printf '{\n'
  printf '  "gateway_commit": "%s",\n' "$COMMIT"
  printf '  "files": {\n'
  last=$((${#FILES[@]} - 1))
  for i in "${!FILES[@]}"; do
    f="${FILES[$i]}"
    sum=$(sha256_file "$DST/$f")
    if [ "$i" -eq "$last" ]; then
      printf '    "%s": "%s"\n' "$f" "$sum"
    else
      printf '    "%s": "%s",\n' "$f" "$sum"
    fi
  done
  printf '  }\n'
  printf '}\n'
} > "$MANIFEST"
echo "wrote MANIFEST.json (gateway commit $COMMIT)"

echo "mirror-golden: ${#FILES[@]} files mirrored from $SRC"
