#!/usr/bin/env bash
# Throwaway gateway e2e harness for gateway-sdk-go.
#
# Boots the private ghcr gateway image with per-run ephemeral config
# (fresh Ed25519 signing keys, generated operator login, ephemeral admin
# TOTP secret in the smoke profile, dummy Xendit values, container-internal
# temp SQLite), waits for GET /health, then removes the container. Never
# targets production: only a local throwaway container is ever started.
#
# Usage: bash scripts/e2e-gateway.sh [--start | --health | --stop | --smoke | --conformance]
#   --start       pull the gateway image and start the throwaway gateway
#   --health      GET /health on the running container (expects 200)
#   --stop        remove the container
#   --smoke       --start + --health + --stop in production mode with an
#                 ephemeral admin TOTP secret (default); the container is
#                 removed even on failure
#   --conformance --start in development mode (APP_MODE=development,
#                 APP_OUTBOUND_ALLOW_INSECURE=1, no APP_ADMIN_TOTP_SECRET,
#                 raised APP_RATE_* limits, host.docker.internal wired to
#                 the host gateway) + --health + go run ./cmd/conformance
#                 + --stop; the container is removed even on failure. The
#                 ephemeral operator username/password reach the runner
#                 through CONFORMANCE_* environment variables only —
#                 never on the command line, never logged.
#
# Env:
#   GATEWAY_IMAGE  image ref (default ghcr.io/konsulin-care/konsulin-gateway:latest;
#                  a local build alias konsulin-gateway:<tag> is also accepted)
#   E2E_PORT       host port published to the container (default 18080)
#
# Requires: docker, openssl, htpasswd (apache2-utils), curl; --conformance
# additionally requires go (it runs `go run ./cmd/conformance`). The private
# ghcr image needs `docker login ghcr.io` first — CI logs in with
# GITHUB_TOKEN and packages: read; locally use a PAT (or `gh auth token`)
# with read:packages.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

GATEWAY_IMAGE="${GATEWAY_IMAGE:-ghcr.io/konsulin-care/konsulin-gateway:latest}"
E2E_PORT="${E2E_PORT:-18080}"
CONTAINER_NAME="gateway-sdk-e2e"
HEALTH_URL="http://127.0.0.1:${E2E_PORT}/health"
START_TIMEOUT_SECS="${START_TIMEOUT_SECS:-90}"

# Per-run operator login, set by start and consumed by run_conformance
# through the CONFORMANCE_* environment. The password is never echoed.
OPERATOR_USER=""
OPERATOR_PASSWORD=""

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
# profile selects the deployment mode: "smoke" is production mode with an
# ephemeral admin TOTP secret (unchanged behavior); "conformance" is
# development mode — APP_MODE=development, APP_OUTBOUND_ALLOW_INSECURE=1,
# no APP_ADMIN_TOTP_SECRET, raised APP_RATE_* limits, and
# host.docker.internal mapped to the host gateway so the container can
# reach host-side listeners.
start() {
  local profile="${1:-smoke}"
  case "$profile" in
    smoke|conformance) ;;
    *) die "unknown start profile: $profile (use smoke | conformance)" ;;
  esac

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

  local gateway_key admin_key operator_hash xendit_token xendit_callback_token totp_secret
  gateway_key=$(gen_ed25519_b64)
  admin_key=$(gen_ed25519_b64)
  [ -n "$gateway_key" ] && [ -n "$admin_key" ] || die "openssl produced no signing key"
  [ "$gateway_key" != "$admin_key" ] || die "gateway and admin signing keys must be distinct"
  if [ "$profile" = "smoke" ]; then
    # 20 random bytes -> 32 unpadded base32 chars, the seed form the gateway's
    # parseTOTPSeed accepts (RFC 4648, no padding); a malformed seed fails its boot.
    totp_secret=$(openssl rand 20 | base32 | tr -d '\n')
    [ -n "$totp_secret" ] || die "openssl produced no TOTP secret"
  fi
  # The operator login is ephemeral per run. The plaintext password stays
  # in this shell only — never echoed, never logged — so the conformance
  # profile can pass it to cmd/conformance through the CONFORMANCE_*
  # environment; the container receives the bcrypt hash.
  OPERATOR_USER="operator"
  OPERATOR_PASSWORD="test-operator-pass-$(openssl rand -hex 8)"
  operator_hash=$(htpasswd -bnBC 12 "" "$OPERATOR_PASSWORD" 2>/dev/null | tr -d ':\n')
  [ -n "$operator_hash" ] || die "htpasswd produced no bcrypt hash"
  xendit_token=$(openssl rand -hex 32)
  xendit_callback_token=$(openssl rand -hex 32)

  # Profile-specific docker args: the conformance profile raises every
  # APP_RATE_* knob so QC-chain traffic never trips 429, maps
  # host.docker.internal to the host gateway (host-gateway), and passes no
  # APP_ADMIN_TOTP_SECRET at all. The smoke profile keeps its TOTP secret
  # and nothing else changes. The ${arr[@]+...} guards keep empty arrays
  # safe under set -u.
  local -a profile_args=() totp_args=()
  if [ "$profile" = "conformance" ]; then
    profile_args=(
      --add-host=host.docker.internal:host-gateway
      -e APP_MODE=development
      -e APP_OUTBOUND_ALLOW_INSECURE=1
      -e APP_RATE_LIMIT_MAX=100000
      -e APP_RATE_PUBLIC_RPS=1000
      -e APP_RATE_PUBLIC_BURST=2000
      -e APP_RATE_CALLBACK_RPS=1000
      -e APP_RATE_CALLBACK_BURST=2000
      -e APP_RATE_PARTY_RPS=1000
      -e APP_RATE_PARTY_BURST=2000
    )
  fi
  if [ "$profile" = "smoke" ]; then
    totp_args=(-e "APP_ADMIN_TOTP_SECRET=${totp_secret}")
  fi

  log "starting throwaway gateway on port $E2E_PORT (profile: $profile)"
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
    ${totp_args[@]+"${totp_args[@]}"} \
    ${profile_args[@]+"${profile_args[@]}"} \
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

# run_conformance runs the SDK conformance suite against the running
# throwaway gateway. The ephemeral operator username/password and the
# base URL reach the runner through the CONFORMANCE_* environment only —
# never on the command line, never logged. A non-zero runner exit (1
# mismatch, 2 usage) propagates as this script's exit status; the EXIT
# trap still removes the container.
run_conformance() {
  command -v go >/dev/null 2>&1 || die "go not found"
  [ -n "${OPERATOR_PASSWORD:-}" ] || die "no operator password in scope; --start conformance must run first"
  log "running cmd/conformance against http://127.0.0.1:${E2E_PORT}"
  CONFORMANCE_BASE_URL="http://127.0.0.1:${E2E_PORT}" \
    CONFORMANCE_OPERATOR_USER="${OPERATOR_USER}" \
    CONFORMANCE_OPERATOR_PASSWORD="${OPERATOR_PASSWORD}" \
    go run ./cmd/conformance
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
    start smoke
    health
    ;;
  --conformance)
    trap stop EXIT
    start conformance
    health
    run_conformance
    ;;
  *)
    die "unknown flag: $MODE (use --start | --health | --stop | --smoke | --conformance)"
    ;;
esac
