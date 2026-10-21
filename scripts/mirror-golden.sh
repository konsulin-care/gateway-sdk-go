#!/usr/bin/env bash
# Mirror the PRD §11 golden vectors from the local gateway checkout into
# testdata/golden/.
#
# Usage: scripts/mirror-golden.sh [gateway-golden-dir]
# Default source: ../gateway/testdata/golden (sibling checkout).
#
# Copies an explicit allow-list of the 12 mirrored files, one cp per file —
# never a glob, never a directory copy. The gateway signing key
# (testonly-gateway-signing-private.key) is never mirrored: a stray copy in
# the destination is removed.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC="${1:-$REPO_ROOT/../gateway/testdata/golden}"
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

if [ ! -d "$SRC" ]; then
  echo "mirror-golden: source directory not found: $SRC" >&2
  exit 1
fi

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
signing_key="testonly-gateway-signing-private.key"
if [ -e "$DST/$signing_key" ]; then
  rm "$DST/$signing_key"
  echo "mirror-golden: removed stray $signing_key from $DST" >&2
fi

echo "mirror-golden: ${#FILES[@]} files mirrored from $SRC"
