#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/integrations/deploy/docker/docker-compose.yml"
SETUP_SCRIPT="${ROOT_DIR}/integrations/deploy/scripts/setup-devnet.sh"
HEALTHCHECK_SCRIPT="${ROOT_DIR}/integrations/deploy/scripts/healthcheck.sh"
PROJECT_NAME="${AETHELRED_DEVNET_PROJECT:-aethelred-devnet}"
GENESIS_FILE="${ROOT_DIR}/tools/devnet/genesis.json"

usage() {
  cat <<'EOF'
Aethelred Devnet Control

Usage:
  scripts/devnet-control.sh <command> [args]

Commands:
  validate       Run static devnet readiness checks
  up             Start the full devnet cluster
  clean-start    Rebuild and start from a clean devnet state
  down           Stop the devnet cluster
  status         Show devnet container status
  logs           Stream devnet logs
  doctor         Run runtime health checks
  endpoints      Print local service endpoints

Examples:
  make devnet-validate
  make devnet-up
  make devnet-doctor
EOF
}

compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" "$@"
    return
  fi

  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" "$@"
    return
  fi

  echo "Docker Compose is required for this devnet command." >&2
  exit 1
}

validate() {
  python3 "${ROOT_DIR}/scripts/validate-devnet-genesis.py" "${GENESIS_FILE}"
  bash "${ROOT_DIR}/scripts/validate-compose-security.sh"
  python3 "${ROOT_DIR}/scripts/validate-devnet-topology.py"

  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    compose config --quiet
  elif command -v docker-compose >/dev/null 2>&1; then
    compose config --quiet
  else
    echo "Docker Compose not found; skipped compose syntax validation."
  fi

  test -f "${ROOT_DIR}/docs/devnet/README.md"
  echo "Devnet readiness validation passed."
}

print_endpoints() {
  cat <<'EOF'
Aethelred Devnet Endpoints

Core services:
  JSON-RPC:      http://localhost:8545
  WebSocket:     ws://localhost:8546
  GraphQL:       http://localhost:8547/graphql
  Faucet:        http://localhost:8080
  Explorer:      http://localhost:4000

Operations:
  Prometheus:    http://localhost:9090
  Grafana:       http://localhost:3000
  Health check:  make devnet-doctor

Network:
  Chain ID:      aethelred-devnet-1
  Compose file:  integrations/deploy/docker/docker-compose.yml
EOF
}

cmd="${1:-help}"
shift || true

case "${cmd}" in
  validate)
    validate "$@"
    ;;
  up)
    bash "${SETUP_SCRIPT}" "$@"
    ;;
  clean-start)
    bash "${SETUP_SCRIPT}" --clean --build "$@"
    ;;
  down)
    compose down "$@"
    ;;
  status)
    compose ps "$@"
    ;;
  logs)
    compose logs -f "$@"
    ;;
  doctor)
    bash "${HEALTHCHECK_SCRIPT}" "$@"
    ;;
  endpoints)
    print_endpoints
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "Unknown devnet command: ${cmd}" >&2
    usage >&2
    exit 1
    ;;
esac
