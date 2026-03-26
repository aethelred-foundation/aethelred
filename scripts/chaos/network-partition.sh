#!/usr/bin/env bash
# ============================================================================
# SQ17 - Chaos: Network Partition Simulation
# ============================================================================
# Simulates a network partition among local testnet validators by using
# iptables (Linux) or pf (macOS) to block traffic between two groups.
# Monitors consensus for the duration, heals the partition, then verifies
# consensus recovery.
#
# Usage:
#   chmod +x scripts/chaos/network-partition.sh
#   sudo ./scripts/chaos/network-partition.sh
#
# Prerequisites:
#   - Local testnet running (Docker or native processes)
#   - Root/sudo access (required for iptables/pf)
#   - curl, jq available
#
# NOTE: This script modifies firewall rules. Always run on test infrastructure
# only. The cleanup trap ensures rules are removed even on script failure.
# ============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PARTITION_DURATION_SECS=${PARTITION_DURATION_SECS:-120}
RECOVERY_WAIT_SECS=${RECOVERY_WAIT_SECS:-60}
POLL_INTERVAL_SECS=${POLL_INTERVAL_SECS:-10}
VALIDATOR_COUNT=${VALIDATOR_COUNT:-4}
RPC_BASE_PORT=${RPC_BASE_PORT:-26657}
P2P_BASE_PORT=${P2P_BASE_PORT:-26656}

# Partition split: Group A = validators 0,1  |  Group B = validators 2,3
# Override with comma-separated indices if needed
GROUP_A_INDICES=${GROUP_A_INDICES:-"0,1"}
GROUP_B_INDICES=${GROUP_B_INDICES:-"2,3"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf "[%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "FAIL: $*" >&2; exit 1; }

get_height() {
  local port="$1"
  curl -fsS "http://127.0.0.1:${port}/status" 2>/dev/null \
    | jq -r '.result.sync_info.latest_block_height // empty' || echo "0"
}

validator_rpc_port() { echo $(( RPC_BASE_PORT + $1 * 100 )); }
validator_p2p_port() { echo $(( P2P_BASE_PORT + $1 * 100 )); }

IFS=',' read -ra GROUP_A <<< "$GROUP_A_INDICES"
IFS=',' read -ra GROUP_B <<< "$GROUP_B_INDICES"

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
PLATFORM="$(uname -s)"
IPTABLES_CHAIN="AETHELRED_CHAOS_PARTITION"

apply_partition_linux() {
  log "Creating iptables chain: ${IPTABLES_CHAIN}"
  iptables -N "${IPTABLES_CHAIN}" 2>/dev/null || iptables -F "${IPTABLES_CHAIN}"

  for a_idx in "${GROUP_A[@]}"; do
    local a_port
    a_port=$(validator_p2p_port "$a_idx")
    for b_idx in "${GROUP_B[@]}"; do
      local b_port
      b_port=$(validator_p2p_port "$b_idx")
      # Block traffic in both directions between groups
      iptables -A "${IPTABLES_CHAIN}" -p tcp --sport "${a_port}" --dport "${b_port}" -j DROP
      iptables -A "${IPTABLES_CHAIN}" -p tcp --sport "${b_port}" --dport "${a_port}" -j DROP
      iptables -A "${IPTABLES_CHAIN}" -p tcp --dport "${a_port}" -m tcp --sport "${b_port}" -j DROP
      iptables -A "${IPTABLES_CHAIN}" -p tcp --dport "${b_port}" -m tcp --sport "${a_port}" -j DROP
    done
  done

  iptables -I INPUT 1 -j "${IPTABLES_CHAIN}"
  iptables -I OUTPUT 1 -j "${IPTABLES_CHAIN}"
}

remove_partition_linux() {
  log "Removing iptables partition rules"
  iptables -D INPUT -j "${IPTABLES_CHAIN}" 2>/dev/null || true
  iptables -D OUTPUT -j "${IPTABLES_CHAIN}" 2>/dev/null || true
  iptables -F "${IPTABLES_CHAIN}" 2>/dev/null || true
  iptables -X "${IPTABLES_CHAIN}" 2>/dev/null || true
}

apply_partition_docker() {
  log "Applying Docker network partition via container network disconnect"
  for a_idx in "${GROUP_A[@]}"; do
    for b_idx in "${GROUP_B[@]}"; do
      local a_container="aethelred-validator-${a_idx}"
      local b_container="aethelred-validator-${b_idx}"
      # Use Docker exec to add iptables rules inside containers
      docker exec "${a_container}" sh -c \
        "iptables -A OUTPUT -p tcp --dport $(validator_p2p_port "$b_idx") -j DROP 2>/dev/null" || true
      docker exec "${b_container}" sh -c \
        "iptables -A OUTPUT -p tcp --dport $(validator_p2p_port "$a_idx") -j DROP 2>/dev/null" || true
    done
  done
}

remove_partition_docker() {
  log "Removing Docker container iptables partition rules"
  for i in $(seq 0 $((VALIDATOR_COUNT - 1))); do
    docker exec "aethelred-validator-${i}" sh -c "iptables -F 2>/dev/null" || true
  done
}

apply_partition_macos() {
  log "Applying pf-based network partition (macOS)"
  local pf_rules="/tmp/aethelred-chaos-partition.conf"
  : > "$pf_rules"
  for a_idx in "${GROUP_A[@]}"; do
    local a_port
    a_port=$(validator_p2p_port "$a_idx")
    for b_idx in "${GROUP_B[@]}"; do
      local b_port
      b_port=$(validator_p2p_port "$b_idx")
      echo "block drop quick proto tcp from any port ${a_port} to any port ${b_port}" >> "$pf_rules"
      echo "block drop quick proto tcp from any port ${b_port} to any port ${a_port}" >> "$pf_rules"
    done
  done
  pfctl -f "$pf_rules" -e 2>/dev/null || pfctl -f "$pf_rules"
}

remove_partition_macos() {
  log "Removing pf partition rules (macOS)"
  pfctl -d 2>/dev/null || true
  rm -f /tmp/aethelred-chaos-partition.conf
}

# ---------------------------------------------------------------------------
# Apply / Remove partition (dispatch)
# ---------------------------------------------------------------------------
apply_partition() {
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "aethelred-validator-"; then
    apply_partition_docker
  elif [[ "$PLATFORM" == "Linux" ]]; then
    apply_partition_linux
  elif [[ "$PLATFORM" == "Darwin" ]]; then
    apply_partition_macos
  else
    fail "Unsupported platform: ${PLATFORM}"
  fi
}

remove_partition() {
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "aethelred-validator-"; then
    remove_partition_docker
  elif [[ "$PLATFORM" == "Linux" ]]; then
    remove_partition_linux
  elif [[ "$PLATFORM" == "Darwin" ]]; then
    remove_partition_macos
  else
    log "WARNING: Could not determine how to remove partition rules"
  fi
}

# Ensure cleanup on exit
trap remove_partition EXIT

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log "=== Network Partition Chaos Test ==="
log "Group A validators : [${GROUP_A_INDICES}]"
log "Group B validators : [${GROUP_B_INDICES}]"
log "Partition duration : ${PARTITION_DURATION_SECS}s"
log "Recovery wait      : ${RECOVERY_WAIT_SECS}s"

# Record pre-partition heights from both groups
GROUP_A_PORT=$(validator_rpc_port "${GROUP_A[0]}")
GROUP_B_PORT=$(validator_rpc_port "${GROUP_B[0]}")

PRE_HEIGHT_A=$(get_height "$GROUP_A_PORT")
PRE_HEIGHT_B=$(get_height "$GROUP_B_PORT")
log "Pre-partition heights: GroupA=${PRE_HEIGHT_A}  GroupB=${PRE_HEIGHT_B}"

# ---------------------------------------------------------------------------
# Phase 1: Apply partition
# ---------------------------------------------------------------------------
log "--- Phase 1: Applying network partition ---"
apply_partition
log "Partition applied"

# ---------------------------------------------------------------------------
# Phase 2: Monitor during partition
# ---------------------------------------------------------------------------
log "--- Phase 2: Monitoring during partition (${PARTITION_DURATION_SECS}s) ---"

ELAPSED=0
while (( ELAPSED < PARTITION_DURATION_SECS )); do
  sleep "$POLL_INTERVAL_SECS"
  ELAPSED=$(( ELAPSED + POLL_INTERVAL_SECS ))

  HEIGHT_A=$(get_height "$GROUP_A_PORT")
  HEIGHT_B=$(get_height "$GROUP_B_PORT")
  log "  t+${ELAPSED}s: GroupA height=${HEIGHT_A}  GroupB height=${HEIGHT_B}"
done

PARTITION_HEIGHT_A=$(get_height "$GROUP_A_PORT")
PARTITION_HEIGHT_B=$(get_height "$GROUP_B_PORT")

# ---------------------------------------------------------------------------
# Phase 3: Heal partition
# ---------------------------------------------------------------------------
log "--- Phase 3: Healing partition ---"
remove_partition
trap - EXIT
log "Partition healed, waiting ${RECOVERY_WAIT_SECS}s for consensus recovery"

sleep "$RECOVERY_WAIT_SECS"

# ---------------------------------------------------------------------------
# Phase 4: Verify recovery
# ---------------------------------------------------------------------------
log "--- Phase 4: Verifying consensus recovery ---"

POST_HEIGHT_A=$(get_height "$GROUP_A_PORT")
POST_HEIGHT_B=$(get_height "$GROUP_B_PORT")

log ""
log "=== Network Partition Test Report ==="
log "Pre-partition : GroupA=${PRE_HEIGHT_A}  GroupB=${PRE_HEIGHT_B}"
log "During partition: GroupA=${PARTITION_HEIGHT_A}  GroupB=${PARTITION_HEIGHT_B}"
log "Post-recovery : GroupA=${POST_HEIGHT_A}  GroupB=${POST_HEIGHT_B}"

# Check if heights converged (within 2 blocks tolerance)
HEIGHT_DIFF=$(( POST_HEIGHT_A > POST_HEIGHT_B ? POST_HEIGHT_A - POST_HEIGHT_B : POST_HEIGHT_B - POST_HEIGHT_A ))
RECOVERY_BLOCKS_A=$(( POST_HEIGHT_A - PARTITION_HEIGHT_A ))

if (( HEIGHT_DIFF <= 2 && RECOVERY_BLOCKS_A > 0 )); then
  log "RESULT: PASS - Consensus recovered after partition heal (height diff: ${HEIGHT_DIFF})"
  exit 0
elif (( RECOVERY_BLOCKS_A > 0 )); then
  log "RESULT: WARN - Chain is producing blocks but heights have not converged (diff: ${HEIGHT_DIFF})"
  exit 0
else
  log "RESULT: FAIL - Consensus did NOT recover after partition heal"
  exit 1
fi
