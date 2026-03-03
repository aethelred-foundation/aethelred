#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/integrations/deploy/docker/docker-compose.local-testnet.yml"

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "Compose file not found: ${COMPOSE_FILE}" >&2
  exit 1
fi

compose() {
  local profile="${AETHELRED_LOCAL_TESTNET_PROFILE:-mock}"
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f "${COMPOSE_FILE}" --profile "${profile}" "$@"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f "${COMPOSE_FILE}" --profile "${profile}" "$@"
    return
  fi
  echo "Docker Compose not found" >&2
  exit 1
}

cmd="${1:-status}"
shift || true

case "${cmd}" in
  up)
    compose up -d "$@"
    ;;
  down)
    compose down "$@"
    ;;
  status)
    compose ps
    ;;
  logs)
    compose logs -f "$@"
    ;;
  doctor)
    curl -fsS http://127.0.0.1:26657/health >/dev/null && echo "✓ rpc" || echo "✗ rpc"
    curl -fsS http://127.0.0.1:8000/health >/dev/null && echo "✓ fastapi-verifier" || echo "✗ fastapi-verifier"
    curl -fsS http://127.0.0.1:3000/api/health >/dev/null && echo "✓ nextjs-verifier" || echo "✗ nextjs-verifier"
    curl -fsS http://127.0.0.1:3101/devtools >/dev/null && echo "✓ dashboard-devtools" || echo "✗ dashboard-devtools"
    ;;
  *)
    echo "Usage: AETHELRED_LOCAL_TESTNET_PROFILE=mock|real-node $0 [up|down|status|logs|doctor] [extra args...]" >&2
    exit 1
    ;;
esac
