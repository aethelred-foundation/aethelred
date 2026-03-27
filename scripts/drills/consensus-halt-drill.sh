#!/usr/bin/env bash
# ============================================================================
# SQ21 - Launch Ops: Consensus Halt Recovery Drill
# ============================================================================
# Rehearses the consensus halt recovery procedure:
#   1. Stops all validators to simulate a halt
#   2. Verifies the chain has halted (no new blocks)
#   3. Restarts validators with the recovery procedure
#   4. Validates the chain resumes producing blocks
#
# Usage:
#   chmod +x scripts/drills/consensus-halt-drill.sh
#   ./scripts/drills/consensus-halt-drill.sh
#
# Prerequisites:
#   - Local testnet running (make local-testnet-up or make testnet-start)
#   - curl, jq available
#   - Docker (if using containerized testnet)
# ============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VALIDATOR_COUNT=${VALIDATOR_COUNT:-4}
RPC_BASE_PORT=${RPC_BASE_PORT:-26657}
HALT_VERIFY_SECS=${HALT_VERIFY_SECS:-15}
RECOVERY_WAIT_SECS=${RECOVERY_WAIT_SECS:-60}
STAGGER_DELAY_SECS=${STAGGER_DELAY_SECS:-3}
DRILL_LOG_DIR="${DRILL_LOG_DIR:-${ROOT_DIR}/test-results}"
DRILL_LOG_FILE="${DRILL_LOG_DIR}/consensus-halt-drill-$(date -u +%Y%m%d-%H%M%S).log"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() {
  local msg
  msg="$(printf "[%s] %s" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*")"
  printf "%s\n" "$msg"
  mkdir -p "$(dirname "$DRILL_LOG_FILE")"
  printf "%s\n" "$msg" >> "$DRILL_LOG_FILE"
}
fail() { log "FAIL: $*" >&2; exit 1; }

validator_rpc_port() { echo $(( RPC_BASE_PORT + $1 * 100 )); }
validator_container() { echo "aethelred-validator-${1}"; }

get_height() {
  local port="$1"
  curl -fsS "http://127.0.0.1:${port}/status" 2>/dev/null \
    | jq -r '.result.sync_info.latest_block_height // empty' || echo "0"
}

is_container_running() {
  docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${1}$"
}

detect_testnet_mode() {
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "aethelred-validator-"; then
    echo "docker"
  else
    echo "process"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
MODE=$(detect_testnet_mode)
log "=== Consensus Halt Recovery Drill ==="
log "Testnet mode    : ${MODE}"
log "Validator count : ${VALIDATOR_COUNT}"
log ""

# Record pre-drill state
PRE_HEIGHT=$(get_height "$(validator_rpc_port 0)")
if [[ "$PRE_HEIGHT" == "0" ]]; then
  fail "Cannot reach validator 0 at port $(validator_rpc_port 0). Is the testnet running?"
fi
log "Pre-drill block height: ${PRE_HEIGHT}"

# ---------------------------------------------------------------------------
# Phase 1: Stop all validators
# ---------------------------------------------------------------------------
log "--- Phase 1: Stopping all validators ---"

for i in $(seq 0 $((VALIDATOR_COUNT - 1))); do
  CONTAINER=$(validator_container "$i")
  PORT=$(validator_rpc_port "$i")

  if [[ "$MODE" == "docker" ]]; then
    if is_container_running "$CONTAINER"; then
      docker stop "$CONTAINER" >/dev/null 2>&1
      log "  Stopped container: ${CONTAINER}"
    else
      log "  Container ${CONTAINER} not running (skipped)"
    fi
  else
    PID=$(lsof -ti "tcp:${PORT}" 2>/dev/null || true)
    if [[ -n "$PID" ]]; then
      kill "$PID" 2>/dev/null || true
      log "  Stopped process PID ${PID} on port ${PORT}"
    else
      log "  No process on port ${PORT} (skipped)"
    fi
  fi
done

# ---------------------------------------------------------------------------
# Phase 2: Verify consensus halt
# ---------------------------------------------------------------------------
log "--- Phase 2: Verifying consensus halt (${HALT_VERIFY_SECS}s) ---"
sleep "$HALT_VERIFY_SECS"

HALT_CONFIRMED=true
for i in $(seq 0 $((VALIDATOR_COUNT - 1))); do
  PORT=$(validator_rpc_port "$i")
  HEIGHT=$(get_height "$PORT")
  if [[ "$HEIGHT" != "0" ]]; then
    HALT_CONFIRMED=false
    log "  WARNING: Validator ${i} still responding at height ${HEIGHT}"
  fi
done

if [[ "$HALT_CONFIRMED" == "true" ]]; then
  log "  Confirmed: All validators are stopped. Chain is halted."
else
  log "  WARNING: Some validators may still be running"
fi

# ---------------------------------------------------------------------------
# Phase 3: Recovery - restart validators with staggered start
# ---------------------------------------------------------------------------
log "--- Phase 3: Restarting validators (staggered, ${STAGGER_DELAY_SECS}s apart) ---"

for i in $(seq 0 $((VALIDATOR_COUNT - 1))); do
  CONTAINER=$(validator_container "$i")

  if [[ "$MODE" == "docker" ]]; then
    docker start "$CONTAINER" >/dev/null 2>&1
    log "  Started container: ${CONTAINER}"
  else
    # For process-based testnet, use the testnet start script
    if [[ -f "${ROOT_DIR}/scripts/testnet.sh" ]]; then
      "${ROOT_DIR}/scripts/testnet.sh" start-node "$i" >/dev/null 2>&1 &
      log "  Started validator ${i} via testnet.sh"
    else
      log "  WARNING: Cannot auto-restart validator ${i} (no testnet.sh). Manual restart needed."
    fi
  fi

  if (( i < VALIDATOR_COUNT - 1 )); then
    sleep "$STAGGER_DELAY_SECS"
  fi
done

# ---------------------------------------------------------------------------
# Phase 4: Validate chain resumes
# ---------------------------------------------------------------------------
log "--- Phase 4: Waiting for chain recovery (${RECOVERY_WAIT_SECS}s) ---"

RECOVERED=false
ELAPSED=0
POLL_INTERVAL=5
FIRST_RECOVERED_HEIGHT=0

while (( ELAPSED < RECOVERY_WAIT_SECS )); do
  sleep "$POLL_INTERVAL"
  ELAPSED=$(( ELAPSED + POLL_INTERVAL ))

  # Try each validator until we get a response
  for i in $(seq 0 $((VALIDATOR_COUNT - 1))); do
    PORT=$(validator_rpc_port "$i")
    HEIGHT=$(get_height "$PORT")
    if [[ "$HEIGHT" != "0" ]] && (( HEIGHT > PRE_HEIGHT )); then
      RECOVERED=true
      FIRST_RECOVERED_HEIGHT=$HEIGHT
      log "  t+${ELAPSED}s: Validator ${i} producing blocks at height ${HEIGHT}"
      break 2
    fi
  done

  log "  t+${ELAPSED}s: Waiting for block production..."
done

# Give a bit more time for full convergence
if [[ "$RECOVERED" == "true" ]]; then
  sleep 10
fi

# Final height check
POST_HEIGHT=0
RESPONDING_VALIDATORS=0
for i in $(seq 0 $((VALIDATOR_COUNT - 1))); do
  PORT=$(validator_rpc_port "$i")
  HEIGHT=$(get_height "$PORT")
  if [[ "$HEIGHT" != "0" ]]; then
    RESPONDING_VALIDATORS=$(( RESPONDING_VALIDATORS + 1 ))
    if (( HEIGHT > POST_HEIGHT )); then
      POST_HEIGHT=$HEIGHT
    fi
  fi
done

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
log ""
log "=== Consensus Halt Drill Report ==="
log "Pre-drill height       : ${PRE_HEIGHT}"
log "Post-recovery height   : ${POST_HEIGHT}"
log "Responding validators  : ${RESPONDING_VALIDATORS}/${VALIDATOR_COUNT}"
log "Recovery achieved      : ${RECOVERED}"

if [[ "$RECOVERED" == "true" ]] && (( POST_HEIGHT > PRE_HEIGHT )); then
  BLOCKS_RECOVERED=$(( POST_HEIGHT - PRE_HEIGHT ))
  log "Blocks since recovery  : ${BLOCKS_RECOVERED}"
  log ""
  log "RESULT: PASS - Chain recovered from complete halt and resumed block production"
  log "Drill log saved to: ${DRILL_LOG_FILE}"
  exit 0
else
  log ""
  log "RESULT: FAIL - Chain did NOT recover within ${RECOVERY_WAIT_SECS}s"
  log "ACTION: Investigate validator logs for startup errors"
  log "Drill log saved to: ${DRILL_LOG_FILE}"
  exit 1
fi
