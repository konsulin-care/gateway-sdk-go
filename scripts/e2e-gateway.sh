#!/usr/bin/env bash
# Throwaway gateway e2e harness for gateway-sdk-go.
#
# Boots the pinned private ghcr gateway image with per-run ephemeral config
# (fresh Ed25519 signing keys, generated operator login, dummy Xendit values,
# container-internal temp SQLite), waits for GET /health, then removes the
# container. Never targets production: only a local throwaway container is
# ever started.
#
# Usage: bash scripts/e2e-gateway.sh [--start | --health | --stop | --smoke]
#   --start  pull the pinned image and start the throwaway gateway
#   --health GET /health on the running container (expects 200)
#   --stop   remove the container
#   --smoke  --start + --health + --stop, container removed even on failure
#            (default)
#
# Env:
#   GATEWAY_IMAGE  image ref (default ghcr.io/konsulin-care/konsulin-gateway:v0.1.1;
#                  a local build alias konsulin-gateway:<tag> is also accepted)
#   E2E_PORT       host port published to the container (default 18080)
#
# Requires: docker, openssl, htpasswd (apache2-utils), curl. The private ghcr
# image needs `docker login ghcr.io` first — CI logs in with GITHUB_TOKEN and
# packages: read; locally use a PAT (or `gh auth token`) with read:packages.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

GATEWAY_IMAGE="${GATEWAY_IMAGE:-ghcr.io/konsulin-care/konsulin-gateway:v0.1.1}"
E2E_PORT="${E2E_PORT:-18080}"
CONTAINER_NAME="gateway-sdk-e2e"
HEALTH_URL="http://127.0.0.1:${E2E_PORT}/health"
START_TIMEOUT_SECS="${START_TIMEOUT_SECS:-90}"

log() { echo "[e2e-gateway] $*" >&2; }
die() { echo "[e2e-gateway] ERROR: $*" >&2; exit 1; }

# Guard rail: only the pinned gateway image (or a local build alias of it)
# may run. A production endpoint is a URL, never an image ref, so no URL
# handling exists here at all.
case "$GATEWAY_IMAGE" in
  ghcr.io/konsulin-care/konsulin-gateway:*|konsulin-gateway:*) ;;
  *) die "GATEWAY_IMAGE ($GATEWAY_IMAGE) is not a konsulin gateway image ref; refusing" ;;
esac

# gen_ed25519_b64 emits a base64 PKCS#8 DER Ed25519 private key — the wire
# form the gateway config accepts for APP_*_SIGNING_KEY.
gen_ed25519_b64() {
  openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | base64 | tr -d '\n'
}

# start pulls the pinned image and launches the throwaway gateway with
# ephemeral per-run config, then blocks until GET /health returns 200.
start() {
  command -v docker >/dev/null 2>&1 || die "docker not found"
  command -v openssl >/dev/null 2>&1 || die "openssl not found"
  command -v htpasswd >/dev/null 2>&1 || die "htpasswd not found (install apache2-utils)"
  command -v curl >/dev/null 2>&1 || die "curl not found"

  if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    log "container $CONTAINER_NAME already running; removing for a fresh run"
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi

  case "$GATEWAY_IMAGE" in
    ghcr.io/*)
      log "pulling $GATEWAY_IMAGE"
      docker pull "$GATEWAY_IMAGE" ||
        die "cannot pull $GATEWAY_IMAGE — for the private ghcr image run: docker login ghcr.io"
      ;;
    *)
      # Local build alias of the gateway image; no registry to pull from.
      docker image inspect "$GATEWAY_IMAGE" >/dev/null 2>&1 ||
        die "local image $GATEWAY_IMAGE not found (build it from ../gateway or use the ghcr ref)"
      log "using local image $GATEWAY_IMAGE"
      ;;
  esac

  local gateway_key admin_key operator_hash xendit_token xendit_callback_token
  gateway_key=$(gen_ed25519_b64)
  admin_key=$(gen_ed25519_b64)
  [ -n "$gateway_key" ] && [ -n "$admin_key" ] || die "openssl produced no signing key"
  [ "$gateway_key" != "$admin_key" ] || die "gateway and admin signing keys must be distinct"
  operator_hash=$(htpasswd -bnBC 10 "" "test-operator-pass-$(openssl rand -hex 8)" 2>/dev/null | tr -d ':\n')
  [ -n "$operator_hash" ] || die "htpasswd produced no bcrypt hash"
  xendit_token=$(openssl rand -hex 32)
  xendit_callback_token=$(openssl rand -hex 32)

  log "starting throwaway gateway on port $E2E_PORT"
  docker run -d --name "$CONTAINER_NAME" -p "${E2E_PORT}:8080" \
    -e APP_PORT=8080 \
    -e APP_DB_PATH=/app/data/gateway.db \
    -e APP_BACKUP_PATH=/app/data/backup \
    -e APP_LOG_LEVEL=error \
    -e "APP_XENDIT_TOKEN=${xendit_token}" \
    -e "APP_XENDIT_CALLBACK_TOKEN=${xendit_callback_token}" \
    -e "APP_GATEWAY_SIGNING_KEY=${gateway_key}" \
    -e "APP_ADMIN_SIGNING_KEY=${admin_key}" \
    -e "APP_OPERATOR_CREDENTIALS=operator:${operator_hash}" \
    "$GATEWAY_IMAGE" >/dev/null

  wait_healthy
}

# wait_healthy polls GET /health until 200, container exit, or timeout.
wait_healthy() {
  local deadline=$((SECONDS + START_TIMEOUT_SECS))
  local code=000
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" != "true" ]; then
      docker logs "$CONTAINER_NAME" 2>&1 | tail -40 >&2 || true
      die "gateway container exited before becoming healthy"
    fi
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$HEALTH_URL" || echo 000)
    if [ "$code" = "200" ]; then
      log "GET $HEALTH_URL -> 200"
      return 0
    fi
    sleep 1
  done
  docker logs "$CONTAINER_NAME" 2>&1 | tail -40 >&2 || true
  die "GET $HEALTH_URL did not return 200 within ${START_TIMEOUT_SECS}s (last status $code)"
}

# health checks GET /health once against the running container.
health() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$HEALTH_URL" || echo 000)
  [ "$code" = "200" ] || die "GET $HEALTH_URL returned $code (expected 200)"
  log "GET $HEALTH_URL -> 200"
}

# stop removes the throwaway container; idempotent.
stop() {
  if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
    log "removed container $CONTAINER_NAME"
  fi
}

MODE="${1:---smoke}"
case "$MODE" in
  --start)
    start
    ;;
  --health)
    health
    ;;
  --stop)
    stop
    ;;
  --smoke)
    trap stop EXIT
    start
    health
    ;;
  *)
    die "unknown flag: $MODE (use --start | --health | --stop | --smoke)"
    ;;
esac
