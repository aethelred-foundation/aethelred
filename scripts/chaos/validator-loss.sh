#!/usr/bin/env bash
# ============================================================================
# SQ17 - Chaos: Validator Loss Simulation
# ============================================================================
# Simulates the loss of a single validator in the local testnet to verify that
# the chain continues producing blocks with a reduced validator set.
#
# Usage:
#   chmod +x scripts/chaos/validator-loss.sh
#   ./scripts/chaos/validator-loss.sh <validator_index>
#
# Prerequisites:
#   - Local testnet running (make local-testnet-up or make testnet-start)
#   - curl available for RPC health checks
#   - jq available for JSON parsing
# ============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MONITOR_DURATION_SECS=${MONITOR_DURATION_SECS:-60}
POLL_INTERVAL_SECS=${POLL_INTERVAL_SECS:-5}
RPC_BASE_PORT=${RPC_BASE_PORT:-26657}
VALIDATOR_COUNT=${VALIDATOR_COUNT:-4}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf "[%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "FAIL: $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 <validator_index>

  validator_index   0-based index of the validator to stop (0..$((VALIDATOR_COUNT - 1)))

Environment variables:
  MONITOR_DURATION_SECS   How long to monitor after stopping (default: 60)
  POLL_INTERVAL_SECS      Polling interval for block height (default: 5)
  RPC_BASE_PORT           Base CometBFT RPC port (default: 26657)
  VALIDATOR_COUNT         Number of validators in the testnet (default: 4)
EOF
  exit 1
}

get_height() {
  local port="$1"
  local result
  result=$(curl -fsS "http://127.0.0.1:${port}/status" 2>/dev/null | jq -r '.result.sync_info.latest_block_height // empty') || true
  echo "${result:-0}"
}

validator_rpc_port() {
  local idx="$1"
  echo $(( RPC_BASE_PORT + idx * 100 ))
}

validator_container_name() {
  local idx="$1"
  echo "aethelred-validator-${idx}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
[[ $# -lt 1 ]] && usage
VALIDATOR_IDX="$1"

if (( VALIDATOR_IDX < 0 || VALIDATOR_IDX >= VALIDATOR_COUNT )); then
  fail "validator_index must be between 0 and $((VALIDATOR_COUNT - 1))"
fi

CONTAINER=$(validator_container_name "$VALIDATOR_IDX")
TARGET_PORT=$(validator_rpc_port "$VALIDATOR_IDX")

# Pick a healthy observer (first validator that is NOT the target)
OBSERVER_PORT=""
for i in $(seq 0 $((VALIDATOR_COUNT - 1))); do
  if [[ "$i" -ne "$VALIDATOR_IDX" ]]; then
    candidate_port=$(validator_rpc_port "$i")
    if curl -fsS "http://127.0.0.1:${candidate_port}/health" >/dev/null 2>&1; then
      OBSERVER_PORT="$candidate_port"
      break
    fi
  fi
done

[[ -z "${OBSERVER_PORT}" ]] && fail "No healthy observer validator found"

log "=== Validator Loss Chaos Test ==="
log "Target validator  : index=${VALIDATOR_IDX}  container=${CONTAINER}  rpc=:${TARGET_PORT}"
log "Observer RPC port : ${OBSERVER_PORT}"
log "Monitor duration  : ${MONITOR_DURATION_SECS}s"

# Record starting height
START_HEIGHT=$(get_height "$OBSERVER_PORT")
log "Starting block height: ${START_HEIGHT}"

# ---------------------------------------------------------------------------
# Phase 1: Stop the target validator
# ---------------------------------------------------------------------------
log "--- Phase 1: Stopping validator ${VALIDATOR_IDX} ---"

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
  docker stop "${CONTAINER}"
  log "Stopped Docker container: ${CONTAINER}"
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "aethelred-validator@${VALIDATOR_IDX}" 2>/dev/null; then
  sudo systemctl stop "aethelred-validator@${VALIDATOR_IDX}"
  log "Stopped systemd unit: aethelred-validator@${VALIDATOR_IDX}"
else
  # Fallback: try to kill the process listening on the target RPC port
  TARGET_PID=$(lsof -ti "tcp:${TARGET_PORT}" 2>/dev/null || true)
  if [[ -n "${TARGET_PID}" ]]; then
    kill "${TARGET_PID}"
    log "Sent SIGTERM to PID ${TARGET_PID} on port ${TARGET_PORT}"
  else
    fail "Could not find validator process for index ${VALIDATOR_IDX}"
  fi
fi

# ---------------------------------------------------------------------------
# Phase 2: Monitor chain progress
# ---------------------------------------------------------------------------
log "--- Phase 2: Monitoring chain for ${MONITOR_DURATION_SECS}s ---"

BLOCKS_PRODUCED=0
MISSED_POLLS=0
ELAPSED=0

while (( ELAPSED < MONITOR_DURATION_SECS )); do
  sleep "$POLL_INTERVAL_SECS"
  ELAPSED=$(( ELAPSED + POLL_INTERVAL_SECS ))

  CURRENT_HEIGHT=$(get_height "$OBSERVER_PORT")
  if [[ "$CURRENT_HEIGHT" == "0" ]]; then
    MISSED_POLLS=$(( MISSED_POLLS + 1 ))
    log "  t+${ELAPSED}s: observer unreachable (missed polls: ${MISSED_POLLS})"
  else
    DELTA=$(( CURRENT_HEIGHT - START_HEIGHT ))
    BLOCKS_PRODUCED=$DELTA
    log "  t+${ELAPSED}s: height=${CURRENT_HEIGHT}  blocks_since_start=${DELTA}"
  fi
done

# ---------------------------------------------------------------------------
# Phase 3: Restart the validator
# ---------------------------------------------------------------------------
log "--- Phase 3: Restarting validator ${VALIDATOR_IDX} ---"

if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
  docker start "${CONTAINER}"
  log "Restarted Docker container: ${CONTAINER}"
elif command -v systemctl >/dev/null 2>&1; then
  sudo systemctl start "aethelred-validator@${VALIDATOR_IDX}"
  log "Restarted systemd unit: aethelred-validator@${VALIDATOR_IDX}"
else
  log "WARNING: Could not auto-restart validator. Manual restart required."
fi

# Wait briefly for validator to catch up
sleep 10
FINAL_HEIGHT=$(get_height "$OBSERVER_PORT")

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
log ""
log "=== Validator Loss Test Report ==="
log "Target validator : ${VALIDATOR_IDX}"
log "Start height     : ${START_HEIGHT}"
log "Final height     : ${FINAL_HEIGHT}"
log "Blocks produced  : ${BLOCKS_PRODUCED}"
log "Missed polls     : ${MISSED_POLLS}"

if (( BLOCKS_PRODUCED > 0 )); then
  log "RESULT: PASS - Chain continued producing blocks without validator ${VALIDATOR_IDX}"
  exit 0
else
  log "RESULT: FAIL - Chain did NOT produce blocks during the observation window"
  exit 1
fi
