#!/usr/bin/env bash
# ============================================================================
# Aethelred DevNet Health Check Script
# ============================================================================
#
# Comprehensive health check script for the Aethelred DevNet cluster.
# Checks all services and reports their status.
#
# Usage:
#   ./healthcheck.sh [--json] [--watch] [--verbose]
#
# Options:
#   --json      Output results as JSON
#   --watch     Continuous monitoring mode (refresh every 5s)
#   --verbose   Show detailed information
#
# Exit Codes:
#   0 - All services healthy
#   1 - One or more services unhealthy
#   2 - Script error
#
# Author: Aethelred Team
# License: Apache-2.0
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Service endpoints
declare -A SERVICES=(
    ["bootnode-rpc"]="http://localhost:26657/health"
    ["validator-alice-rpc"]="http://localhost:26658/health"
    ["validator-bob-rpc"]="http://localhost:26659/health"
    ["compute-charlie-rpc"]="http://localhost:26660/health"
    ["bridge-relayer"]="http://localhost:8080/health"
    ["faucet"]="http://localhost:8081/health"
    ["explorer"]="http://localhost:3000/api/health"
    ["prometheus"]="http://localhost:9091/-/healthy"
    ["grafana"]="http://localhost:3001/api/health"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Options
OUTPUT_JSON=false
WATCH_MODE=false
VERBOSE=false
WATCH_INTERVAL=5

# ============================================================================
# Utility Functions
# ============================================================================

log_info() {
    if ! $OUTPUT_JSON; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_success() {
    if ! $OUTPUT_JSON; then
        echo -e "${GREEN}[✓]${NC} $1"
    fi
}

log_warning() {
    if ! $OUTPUT_JSON; then
        echo -e "${YELLOW}[!]${NC} $1"
    fi
}

log_error() {
    if ! $OUTPUT_JSON; then
        echo -e "${RED}[✗]${NC} $1"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --json)
                OUTPUT_JSON=true
                shift
                ;;
            --watch)
                WATCH_MODE=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --interval)
                WATCH_INTERVAL="$2"
                shift 2
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                print_usage
                exit 2
                ;;
        esac
    done
}

print_usage() {
    cat << EOF
Aethelred DevNet Health Check Script

Usage: $0 [OPTIONS]

Options:
    --json          Output results as JSON
    --watch         Continuous monitoring mode
    --interval N    Watch interval in seconds (default: 5)
    --verbose       Show detailed information
    -h, --help      Show this help message

Examples:
    # Quick health check
    $0

    # JSON output for automation
    $0 --json

    # Continuous monitoring
    $0 --watch --interval 10
EOF
}

# ============================================================================
# Health Check Functions
# ============================================================================

check_service() {
    local name="$1"
    local url="$2"
    local timeout=5
    local start_time=$(date +%s%N)

    local http_code
    local response

    if response=$(curl -sf -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url" 2>/dev/null); then
        http_code="$response"
    else
        http_code="000"
    fi

    local end_time=$(date +%s%N)
    local latency=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds

    if [[ "$http_code" == "200" ]]; then
        echo "healthy|${latency}|${http_code}"
    else
        echo "unhealthy|${latency}|${http_code}"
    fi
}

check_docker_container() {
    local container="$1"

    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
        local status=$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null)
        local health=$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")

        echo "${status}|${health}"
    else
        echo "not_found|none"
    fi
}

get_block_height() {
    local url="$1"

    local height
    if height=$(curl -sf --max-time 5 "${url}/status" 2>/dev/null | grep -o '"latest_block_height":"[0-9]*"' | grep -o '[0-9]*'); then
        echo "$height"
    else
        echo "0"
    fi
}

get_peer_count() {
    local url="$1"

    local count
    if count=$(curl -sf --max-time 5 "${url}/net_info" 2>/dev/null | grep -o '"n_peers":"[0-9]*"' | grep -o '[0-9]*'); then
        echo "$count"
    else
        echo "0"
    fi
}

# ============================================================================
# Output Functions
# ============================================================================

output_text_header() {
    clear 2>/dev/null || true
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║                    AETHELRED DEVNET HEALTH CHECK                          ║"
    echo "╠═══════════════════════════════════════════════════════════════════════════╣"
    echo "║  Timestamp: $(date '+%Y-%m-%d %H:%M:%S')                                         ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo ""
}

output_text_results() {
    local -n results_ref=$1
    local all_healthy=true

    printf "%-25s %-12s %-12s %-10s\n" "SERVICE" "STATUS" "LATENCY" "HTTP CODE"
    printf "%-25s %-12s %-12s %-10s\n" "───────────────────────" "──────────" "──────────" "────────"

    for service in "${!results_ref[@]}"; do
        IFS='|' read -r status latency http_code <<< "${results_ref[$service]}"

        local status_color
        if [[ "$status" == "healthy" ]]; then
            status_color="${GREEN}✓ healthy${NC}"
        else
            status_color="${RED}✗ unhealthy${NC}"
            all_healthy=false
        fi

        printf "%-25s %-22b %-12s %-10s\n" "$service" "$status_color" "${latency}ms" "$http_code"
    done

    echo ""

    if $all_healthy; then
        echo -e "${GREEN}All services are healthy!${NC}"
        return 0
    else
        echo -e "${RED}Some services are unhealthy!${NC}"
        return 1
    fi
}

output_text_blockchain_info() {
    echo ""
    echo "┌─────────────────────────────────────────────────────────────────────────────┐"
    echo "│                           BLOCKCHAIN STATUS                                 │"
    echo "├─────────────────────────────────────────────────────────────────────────────┤"

    local bootnode_height=$(get_block_height "http://localhost:26657")
    local alice_height=$(get_block_height "http://localhost:26658")
    local bob_height=$(get_block_height "http://localhost:26659")
    local peer_count=$(get_peer_count "http://localhost:26657")

    printf "│  Block Height (bootnode):    %-48s│\n" "$bootnode_height"
    printf "│  Block Height (alice):       %-48s│\n" "$alice_height"
    printf "│  Block Height (bob):         %-48s│\n" "$bob_height"
    printf "│  Peer Count:                 %-48s│\n" "$peer_count"

    # Check if blocks are in sync
    if [[ "$bootnode_height" -gt 0 ]] && [[ "$alice_height" -gt 0 ]] && [[ "$bob_height" -gt 0 ]]; then
        local max_height=$bootnode_height
        [[ $alice_height -gt $max_height ]] && max_height=$alice_height
        [[ $bob_height -gt $max_height ]] && max_height=$bob_height

        local min_height=$bootnode_height
        [[ $alice_height -lt $min_height ]] && min_height=$alice_height
        [[ $bob_height -lt $min_height ]] && min_height=$bob_height

        local diff=$((max_height - min_height))
        if [[ $diff -le 2 ]]; then
            printf "│  Sync Status:                %-48s│\n" "✓ In Sync"
        else
            printf "│  Sync Status:                %-48s│\n" "⚠ Out of Sync (diff: $diff)"
        fi
    else
        printf "│  Sync Status:                %-48s│\n" "⚠ Checking..."
    fi

    echo "└─────────────────────────────────────────────────────────────────────────────┘"
}

output_json_results() {
    local -n results_ref=$1
    local all_healthy=true

    echo "{"
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"services\": {"

    local first=true
    for service in "${!results_ref[@]}"; do
        IFS='|' read -r status latency http_code <<< "${results_ref[$service]}"

        if [[ "$status" != "healthy" ]]; then
            all_healthy=false
        fi

        if ! $first; then
            echo ","
        fi
        first=false

        echo -n "    \"${service}\": {"
        echo -n "\"status\": \"${status}\", "
        echo -n "\"latency_ms\": ${latency}, "
        echo -n "\"http_code\": \"${http_code}\""
        echo -n "}"
    done

    echo ""
    echo "  },"
    echo "  \"blockchain\": {"

    local bootnode_height=$(get_block_height "http://localhost:26657")
    local peer_count=$(get_peer_count "http://localhost:26657")

    echo "    \"block_height\": ${bootnode_height},"
    echo "    \"peer_count\": ${peer_count}"
    echo "  },"

    if $all_healthy; then
        echo "  \"overall_status\": \"healthy\""
    else
        echo "  \"overall_status\": \"unhealthy\""
    fi

    echo "}"
}

# ============================================================================
# Main Check Function
# ============================================================================

run_health_check() {
    declare -A results

    # Check all services
    for service in "${!SERVICES[@]}"; do
        results["$service"]=$(check_service "$service" "${SERVICES[$service]}")
    done

    local exit_code=0

    if $OUTPUT_JSON; then
        output_json_results results
        for result in "${results[@]}"; do
            IFS='|' read -r status _ _ <<< "$result"
            if [[ "$status" != "healthy" ]]; then
                exit_code=1
            fi
        done
    else
        output_text_header
        output_text_results results || exit_code=1

        if $VERBOSE; then
            output_text_blockchain_info
        fi
    fi

    return $exit_code
}

# ============================================================================
# Main
# ============================================================================

main() {
    parse_args "$@"

    if $WATCH_MODE; then
        while true; do
            run_health_check || true
            if ! $OUTPUT_JSON; then
                echo ""
                echo "Press Ctrl+C to stop. Refreshing in ${WATCH_INTERVAL}s..."
            fi
            sleep "$WATCH_INTERVAL"
        done
    else
        run_health_check
        exit $?
    fi
}

main "$@"
