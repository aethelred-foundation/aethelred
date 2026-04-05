#!/bin/bash
# =============================================================================
# Aethelred Validator Failover Promotion Script
# =============================================================================
#
# CRITICAL SECURITY NOTICE:
# This script promotes a failover validator to primary. Running this script
# when the primary is still active will result in DOUBLE SIGNING and a
# 50% STAKE SLASH.
#
# REQUIREMENTS:
# 1. Primary validator must be confirmed DEAD for at least 5 minutes
# 2. Primary has not signed for at least 100 blocks
# 3. HSM session on primary must be terminated
#
# USAGE:
#   ./promote_failover.sh [--force] [--no-notify]
#
# OPTIONS:
#   --force     Skip confirmation prompts (DANGEROUS)
#   --no-notify Skip Slack/PagerDuty notifications
#
# =============================================================================

set -euo pipefail

# Configuration
readonly SCRIPT_NAME="promote_failover.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/aethelred/failover.log"

# Load environment
if [[ -f /etc/aethelred/failover.env ]]; then
    source /etc/aethelred/failover.env
else
    echo "ERROR: /etc/aethelred/failover.env not found"
    exit 1
fi

# Required environment variables
: "${PRIMARY_HOST:?PRIMARY_HOST not set}"
: "${VALIDATOR_ADDRESS:?VALIDATOR_ADDRESS not set}"
: "${HSM_PIN:?HSM_PIN not set}"
: "${HSM_KEY_LABEL:?HSM_KEY_LABEL not set}"
: "${HSM_MODULE_PATH:=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so}"
: "${API_ENDPOINT:=https://api.mainnet.aethelred.io}"
: "${SLACK_WEBHOOK:=}"
: "${PAGERDUTY_KEY:=}"

# Safety thresholds
readonly MIN_MISSED_BLOCKS=100
readonly PRIMARY_CHECK_ATTEMPTS=10
readonly PRIMARY_CHECK_INTERVAL=30

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Logging
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$*"; }
log_warn() { log "WARN" "${YELLOW}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }
log_success() { log "SUCCESS" "${GREEN}$*${NC}"; }

# Send notification
notify() {
    local message="$1"
    local severity="${2:-warning}"

    if [[ -n "$SLACK_WEBHOOK" && "$NOTIFY_ENABLED" == "true" ]]; then
        local emoji="⚠️"
        [[ "$severity" == "critical" ]] && emoji="🚨"
        [[ "$severity" == "success" ]] && emoji="✅"

        curl -s -X POST "$SLACK_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"${emoji} FAILOVER: ${message}\", \"username\": \"Aethelred Failover\"}" \
            || log_warn "Failed to send Slack notification"
    fi

    if [[ -n "$PAGERDUTY_KEY" && "$NOTIFY_ENABLED" == "true" && "$severity" == "critical" ]]; then
        curl -s -X POST "https://events.pagerduty.com/v2/enqueue" \
            -H 'Content-Type: application/json' \
            -d "{
                \"routing_key\": \"${PAGERDUTY_KEY}\",
                \"event_action\": \"trigger\",
                \"payload\": {
                    \"summary\": \"Aethelred Failover: ${message}\",
                    \"severity\": \"critical\",
                    \"source\": \"failover-script\"
                }
            }" || log_warn "Failed to send PagerDuty notification"
    fi
}

# Check if primary is reachable
check_primary_alive() {
    log_info "Checking if primary ($PRIMARY_HOST) is reachable..."

    if ping -c 1 -W 5 "$PRIMARY_HOST" &>/dev/null; then
        return 0  # Primary is alive
    fi

    if ssh -o ConnectTimeout=10 -o BatchMode=yes "$PRIMARY_HOST" "echo alive" &>/dev/null; then
        return 0  # Primary is alive
    fi

    return 1  # Primary is dead
}

# Get last signed block from API
get_last_signed_block() {
    local response
    response=$(curl -s "${API_ENDPOINT}/validators/${VALIDATOR_ADDRESS}/signing_info" 2>/dev/null)

    if [[ -z "$response" ]]; then
        log_error "Failed to query API for signing info"
        return 1
    fi

    echo "$response" | jq -r '.last_signed_block // "0"'
}

# Get current block height
get_current_height() {
    local response
    response=$(curl -s "${API_ENDPOINT}/status" 2>/dev/null)

    if [[ -z "$response" ]]; then
        log_error "Failed to query API for current height"
        return 1
    fi

    echo "$response" | jq -r '.sync_info.latest_block_height // "0"'
}

# Check if primary is still signing
check_primary_not_signing() {
    local last_signed
    local current_height

    last_signed=$(get_last_signed_block)
    current_height=$(get_current_height)

    if [[ -z "$last_signed" || -z "$current_height" ]]; then
        log_error "Could not determine signing status"
        return 1
    fi

    local blocks_missed=$((current_height - last_signed))
    log_info "Primary last signed at block $last_signed, current height $current_height (missed $blocks_missed blocks)"

    if [[ $blocks_missed -lt $MIN_MISSED_BLOCKS ]]; then
        log_error "Primary may still be active! Only $blocks_missed blocks missed (need $MIN_MISSED_BLOCKS)"
        return 1
    fi

    log_success "Primary has missed $blocks_missed blocks (threshold: $MIN_MISSED_BLOCKS)"
    return 0
}

# Terminate HSM session on primary
terminate_primary_hsm() {
    log_info "Attempting to terminate HSM session on primary..."

    if ssh -o ConnectTimeout=10 -o BatchMode=yes "$PRIMARY_HOST" \
        "pkcs11-tool --module $HSM_MODULE_PATH --logout 2>/dev/null" &>/dev/null; then
        log_success "Primary HSM session terminated"
        return 0
    fi

    log_warn "Could not terminate primary HSM session (may already be dead)"
    return 0  # Continue anyway - primary might be completely dead
}

# Activate HSM on failover
activate_failover_hsm() {
    log_info "Activating HSM session on failover..."

    if ! pkcs11-tool --module "$HSM_MODULE_PATH" \
        --login --pin "$HSM_PIN" \
        --list-objects 2>/dev/null | grep -q "$HSM_KEY_LABEL"; then
        log_error "Failed to access HSM key: $HSM_KEY_LABEL"
        return 1
    fi

    log_success "HSM session activated, key '$HSM_KEY_LABEL' accessible"
    return 0
}

# Start the failover validator
start_failover_validator() {
    log_info "Starting failover validator..."

    if docker ps --format '{{.Names}}' | grep -q "aethelred-validator"; then
        log_info "Validator container already running, restarting..."
        docker restart aethelred-validator
    else
        docker start aethelred-validator
    fi

    # Wait for startup
    sleep 10

    # Verify it's running
    if ! docker ps --format '{{.Names}}' | grep -q "aethelred-validator"; then
        log_error "Validator container failed to start"
        return 1
    fi

    log_success "Validator container started"
    return 0
}

# Verify failover is signing
verify_signing() {
    log_info "Verifying failover is signing blocks..."

    local attempts=0
    local max_attempts=12  # 2 minutes (6s block time * 12)

    while [[ $attempts -lt $max_attempts ]]; do
        sleep 10

        local last_signed
        last_signed=$(get_last_signed_block)
        local current_height
        current_height=$(get_current_height)

        local blocks_behind=$((current_height - last_signed))

        if [[ $blocks_behind -lt 3 ]]; then
            log_success "Failover is signing! Last signed: $last_signed, current: $current_height"
            return 0
        fi

        log_info "Waiting for signing... ($attempts/$max_attempts)"
        ((attempts++))
    done

    log_error "Failover does not appear to be signing after 2 minutes"
    return 1
}

# Main failover procedure
main() {
    local force=false
    local notify_enabled=true

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force)
                force=true
                shift
                ;;
            --no-notify)
                notify_enabled=false
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    export NOTIFY_ENABLED="$notify_enabled"

    echo ""
    echo "============================================================================="
    echo "        AETHELRED VALIDATOR FAILOVER PROMOTION"
    echo "============================================================================="
    echo ""
    echo "  Validator: $VALIDATOR_ADDRESS"
    echo "  Primary:   $PRIMARY_HOST"
    echo "  HSM Key:   $HSM_KEY_LABEL"
    echo ""

    if [[ "$force" != "true" ]]; then
        echo -e "${RED}WARNING: Promoting failover when primary is still active${NC}"
        echo -e "${RED}         will result in DOUBLE SIGNING and 50% STAKE SLASH!${NC}"
        echo ""
        read -p "Type 'I UNDERSTAND' to continue: " confirmation

        if [[ "$confirmation" != "I UNDERSTAND" ]]; then
            log_error "Failover aborted by user"
            exit 1
        fi
    fi

    notify "Failover promotion initiated for $VALIDATOR_ADDRESS" "warning"

    # Step 1: Verify primary is unreachable
    log_info "=== Step 1: Verifying primary is unreachable ==="

    local primary_alive_count=0
    for i in $(seq 1 $PRIMARY_CHECK_ATTEMPTS); do
        log_info "Check $i/$PRIMARY_CHECK_ATTEMPTS..."

        if check_primary_alive; then
            log_error "PRIMARY IS STILL ALIVE! Aborting failover."
            notify "FAILOVER ABORTED: Primary is still alive!" "critical"
            exit 1
        fi

        sleep $PRIMARY_CHECK_INTERVAL
    done

    log_success "Primary confirmed unreachable after ${PRIMARY_CHECK_ATTEMPTS} attempts"

    # Step 2: Verify primary is not signing
    log_info "=== Step 2: Verifying primary is not signing ==="

    if ! check_primary_not_signing; then
        log_error "Primary may still be signing! Aborting failover."
        notify "FAILOVER ABORTED: Primary may still be signing!" "critical"
        exit 1
    fi

    # Step 3: Terminate primary HSM session
    log_info "=== Step 3: Terminating primary HSM session ==="
    terminate_primary_hsm

    # Step 4: Activate failover HSM
    log_info "=== Step 4: Activating failover HSM ==="

    if ! activate_failover_hsm; then
        log_error "Failed to activate failover HSM"
        notify "FAILOVER FAILED: Could not activate HSM!" "critical"
        exit 1
    fi

    # Step 5: Start failover validator
    log_info "=== Step 5: Starting failover validator ==="

    if ! start_failover_validator; then
        log_error "Failed to start failover validator"
        notify "FAILOVER FAILED: Could not start validator!" "critical"
        exit 1
    fi

    # Step 6: Verify signing
    log_info "=== Step 6: Verifying failover is signing ==="

    if ! verify_signing; then
        log_error "Failover validator is not signing!"
        notify "FAILOVER WARNING: Validator started but not signing!" "critical"
        exit 1
    fi

    # Success!
    echo ""
    echo "============================================================================="
    echo -e "        ${GREEN}FAILOVER COMPLETE${NC}"
    echo "============================================================================="
    echo ""
    echo "  Failover validator is now ACTIVE and SIGNING"
    echo ""
    echo "  NEXT STEPS:"
    echo "  1. Investigate primary failure"
    echo "  2. Do NOT restart primary until HSM session is verified terminated"
    echo "  3. Update DNS/monitoring to point to failover"
    echo ""

    notify "Failover COMPLETE for $VALIDATOR_ADDRESS. Failover is now signing blocks." "success"

    log_success "Failover promotion completed successfully"
}

# Run main
main "$@"
