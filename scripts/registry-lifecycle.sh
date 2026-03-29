#!/usr/bin/env bash
# registry-lifecycle.sh
#
# Operator-grade lifecycle management for Aethelred TEE measurement
# and zkML circuit registries. All mutations are logged to a structured
# JSON audit trail.
#
# Usage:
#   ./scripts/registry-lifecycle.sh <command> [options]
#
# Commands:
#   activate   Register a new measurement or circuit hash
#   revoke     Revoke an existing entry
#   audit      Show registry mutations since a given date
#   export     Export current registry state
#   list       List registry entries
#   verify     Check if a hash is active
#
# Examples:
#   ./scripts/registry-lifecycle.sh activate --type measurement --hash abc123 --signature def456
#   ./scripts/registry-lifecycle.sh revoke --type circuit --hash abc123 --reason "Key rotation"
#   ./scripts/registry-lifecycle.sh audit --since 2025-01-01
#   ./scripts/registry-lifecycle.sh export --format json
#   ./scripts/registry-lifecycle.sh list --status active
#   ./scripts/registry-lifecycle.sh verify --hash abc123
#
# Environment:
#   AETHELRED_REGISTRY_DIR  Registry data directory (default: ~/.aethelred/registry)
#   AETHELRED_OPERATOR_ID   Operator identity for audit trail (default: $(whoami))
#
# Exit codes:
#   0 - Success
#   1 - Operation failed / entry not found
#   2 - Invalid arguments or missing dependencies

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

REGISTRY_DIR="${AETHELRED_REGISTRY_DIR:-$HOME/.aethelred/registry}"
OPERATOR_ID="${AETHELRED_OPERATOR_ID:-$(whoami)}"
MEASUREMENT_REGISTRY="$REGISTRY_DIR/measurements.json"
CIRCUIT_REGISTRY="$REGISTRY_DIR/circuits.json"
AUDIT_LOG="$REGISTRY_DIR/audit.jsonl"
LOCK_FILE="$REGISTRY_DIR/.lock"

# ============================================================================
# Initialization
# ============================================================================

init_registry() {
    mkdir -p "$REGISTRY_DIR"

    if [[ ! -f "$MEASUREMENT_REGISTRY" ]]; then
        echo '{"entries":[]}' > "$MEASUREMENT_REGISTRY"
    fi
    if [[ ! -f "$CIRCUIT_REGISTRY" ]]; then
        echo '{"entries":[]}' > "$CIRCUIT_REGISTRY"
    fi
    if [[ ! -f "$AUDIT_LOG" ]]; then
        touch "$AUDIT_LOG"
    fi
}

# ============================================================================
# Locking (advisory file lock for concurrent operator safety)
# ============================================================================

acquire_lock() {
    local retries=10
    local wait=1
    for (( i=0; i<retries; i++ )); do
        if ( set -o noclobber; echo "$$" > "$LOCK_FILE" ) 2>/dev/null; then
            trap 'rm -f "$LOCK_FILE"' EXIT
            return 0
        fi
        sleep "$wait"
    done
    echo "ERROR: Could not acquire registry lock after ${retries}s" >&2
    exit 2
}

release_lock() {
    rm -f "$LOCK_FILE"
}

# ============================================================================
# Audit logging
# ============================================================================

audit_log() {
    local action="$1"
    local entry_type="$2"
    local hash="$3"
    local details="$4"

    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    local log_entry
    log_entry=$(cat <<EOF
{"timestamp":"$timestamp","operator":"$OPERATOR_ID","action":"$action","type":"$entry_type","hash":"$hash","details":$details,"hostname":"$(hostname)","pid":$$}
EOF
)
    echo "$log_entry" >> "$AUDIT_LOG"
}

# ============================================================================
# Registry helpers
# ============================================================================

get_registry_file() {
    local entry_type="$1"
    case "$entry_type" in
        measurement) echo "$MEASUREMENT_REGISTRY" ;;
        circuit)     echo "$CIRCUIT_REGISTRY" ;;
        *)
            echo "ERROR: Invalid type '$entry_type'. Must be 'measurement' or 'circuit'" >&2
            exit 2
            ;;
    esac
}

validate_hex() {
    local value="$1"
    local name="$2"
    if [[ ! "$value" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "ERROR: $name must be a hexadecimal string, got '$value'" >&2
        exit 2
    fi
}

hash_exists() {
    local registry_file="$1"
    local hash="$2"

    if command -v jq &>/dev/null; then
        jq -e --arg h "$hash" '.entries[] | select(.hash == $h)' "$registry_file" >/dev/null 2>&1
    else
        grep -q "\"hash\":\"$hash\"" "$registry_file"
    fi
}

hash_is_active() {
    local registry_file="$1"
    local hash="$2"

    if command -v jq &>/dev/null; then
        jq -e --arg h "$hash" '.entries[] | select(.hash == $h and .status == "active")' "$registry_file" >/dev/null 2>&1
    else
        grep -q "\"hash\":\"$hash\".*\"status\":\"active\"" "$registry_file"
    fi
}

# ============================================================================
# Commands
# ============================================================================

cmd_activate() {
    local entry_type=""
    local hash=""
    local signature=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)      entry_type="$2"; shift 2 ;;
            --hash)      hash="$2"; shift 2 ;;
            --signature) signature="$2"; shift 2 ;;
            *) echo "ERROR: Unknown option for activate: $1" >&2; exit 2 ;;
        esac
    done

    if [[ -z "$entry_type" || -z "$hash" || -z "$signature" ]]; then
        echo "ERROR: activate requires --type, --hash, and --signature" >&2
        exit 2
    fi

    validate_hex "$hash" "hash"
    validate_hex "$signature" "signature"

    local registry_file
    registry_file=$(get_registry_file "$entry_type")

    acquire_lock

    if hash_exists "$registry_file" "$hash"; then
        echo "ERROR: Hash $hash already exists in $entry_type registry" >&2
        release_lock
        exit 1
    fi

    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    if command -v jq &>/dev/null; then
        local new_entry
        new_entry=$(jq -n \
            --arg h "$hash" \
            --arg s "$signature" \
            --arg t "$timestamp" \
            --arg o "$OPERATOR_ID" \
            '{hash: $h, signature: $s, status: "active", activated_at: $t, activated_by: $o}')

        jq --argjson entry "$new_entry" '.entries += [$entry]' "$registry_file" > "${registry_file}.tmp"
        mv "${registry_file}.tmp" "$registry_file"
    else
        # Fallback: simple sed-based JSON manipulation
        local entry_json="{\"hash\":\"$hash\",\"signature\":\"$signature\",\"status\":\"active\",\"activated_at\":\"$timestamp\",\"activated_by\":\"$OPERATOR_ID\"}"
        # Insert before the closing bracket of the entries array
        if grep -q '"entries":\[\]' "$registry_file"; then
            sed -i.bak "s/\"entries\":\[\]/\"entries\":[$entry_json]/" "$registry_file"
        else
            sed -i.bak "s/\]}/,$entry_json]}/" "$registry_file"
        fi
        rm -f "${registry_file}.bak"
    fi

    audit_log "activate" "$entry_type" "$hash" "{\"signature\":\"$signature\"}"

    release_lock

    echo "OK: Activated $entry_type $hash"
    echo "  Type:      $entry_type"
    echo "  Hash:      $hash"
    echo "  Signature: $signature"
    echo "  Time:      $timestamp"
    echo "  Operator:  $OPERATOR_ID"
}

cmd_revoke() {
    local entry_type=""
    local hash=""
    local reason=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)   entry_type="$2"; shift 2 ;;
            --hash)   hash="$2"; shift 2 ;;
            --reason) reason="$2"; shift 2 ;;
            *) echo "ERROR: Unknown option for revoke: $1" >&2; exit 2 ;;
        esac
    done

    if [[ -z "$entry_type" || -z "$hash" || -z "$reason" ]]; then
        echo "ERROR: revoke requires --type, --hash, and --reason" >&2
        exit 2
    fi

    validate_hex "$hash" "hash"

    local registry_file
    registry_file=$(get_registry_file "$entry_type")

    acquire_lock

    if ! hash_exists "$registry_file" "$hash"; then
        echo "ERROR: Hash $hash not found in $entry_type registry" >&2
        release_lock
        exit 1
    fi

    if ! hash_is_active "$registry_file" "$hash"; then
        echo "ERROR: Hash $hash is already revoked in $entry_type registry" >&2
        release_lock
        exit 1
    fi

    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    if command -v jq &>/dev/null; then
        jq --arg h "$hash" --arg r "$reason" --arg t "$timestamp" --arg o "$OPERATOR_ID" \
            '(.entries[] | select(.hash == $h)) |= . + {status: "revoked", revoked_at: $t, revoked_by: $o, revocation_reason: $r}' \
            "$registry_file" > "${registry_file}.tmp"
        mv "${registry_file}.tmp" "$registry_file"
    else
        sed -i.bak "s/\"hash\":\"$hash\",\(.*\)\"status\":\"active\"/\"hash\":\"$hash\",\1\"status\":\"revoked\",\"revoked_at\":\"$timestamp\",\"revoked_by\":\"$OPERATOR_ID\",\"revocation_reason\":\"$reason\"/" "$registry_file"
        rm -f "${registry_file}.bak"
    fi

    # Escape reason for JSON
    local escaped_reason
    escaped_reason=$(echo "$reason" | sed 's/"/\\"/g')
    audit_log "revoke" "$entry_type" "$hash" "{\"reason\":\"$escaped_reason\"}"

    release_lock

    echo "OK: Revoked $entry_type $hash"
    echo "  Type:   $entry_type"
    echo "  Hash:   $hash"
    echo "  Reason: $reason"
    echo "  Time:   $timestamp"
    echo "  Operator: $OPERATOR_ID"
}

cmd_audit() {
    local since=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --since) since="$2"; shift 2 ;;
            *) echo "ERROR: Unknown option for audit: $1" >&2; exit 2 ;;
        esac
    done

    if [[ -z "$since" ]]; then
        echo "ERROR: audit requires --since <date> (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)" >&2
        exit 2
    fi

    if [[ ! -f "$AUDIT_LOG" ]]; then
        echo "No audit entries found."
        return 0
    fi

    local count=0

    if command -v jq &>/dev/null; then
        echo "=== Registry Audit Log (since $since) ==="
        echo ""
        while IFS= read -r line; do
            local ts
            ts=$(echo "$line" | jq -r '.timestamp' 2>/dev/null || echo "")
            if [[ -n "$ts" && "$ts" > "$since" ]]; then
                echo "$line" | jq '.'
                echo "---"
                count=$((count + 1))
            fi
        done < "$AUDIT_LOG"
    else
        echo "=== Registry Audit Log (since $since) ==="
        echo ""
        while IFS= read -r line; do
            local ts
            ts=$(echo "$line" | grep -o '"timestamp":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
            if [[ -n "$ts" && "$ts" > "$since" ]]; then
                echo "$line"
                count=$((count + 1))
            fi
        done < "$AUDIT_LOG"
    fi

    echo ""
    echo "Total entries: $count"
}

cmd_export() {
    local format="json"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --format) format="$2"; shift 2 ;;
            *) echo "ERROR: Unknown option for export: $1" >&2; exit 2 ;;
        esac
    done

    case "$format" in
        json)
            if command -v jq &>/dev/null; then
                local timestamp
                timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
                jq -n \
                    --arg ts "$timestamp" \
                    --slurpfile m "$MEASUREMENT_REGISTRY" \
                    --slurpfile c "$CIRCUIT_REGISTRY" \
                    '{export_timestamp: $ts, measurements: $m[0].entries, circuits: $c[0].entries}'
            else
                echo "{"
                echo "  \"export_timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
                echo "  \"measurements\": $(cat "$MEASUREMENT_REGISTRY" | grep -o '"entries":\[.*\]' | sed 's/"entries"://'),"
                echo "  \"circuits\": $(cat "$CIRCUIT_REGISTRY" | grep -o '"entries":\[.*\]' | sed 's/"entries"://')"
                echo "}"
            fi
            ;;
        csv)
            echo "type,hash,status,signature,activated_at,activated_by,revoked_at,revoked_by,revocation_reason"
            if command -v jq &>/dev/null; then
                jq -r '.entries[] | ["measurement", .hash, .status, .signature, .activated_at, .activated_by, (.revoked_at // ""), (.revoked_by // ""), (.revocation_reason // "")] | @csv' "$MEASUREMENT_REGISTRY" 2>/dev/null || true
                jq -r '.entries[] | ["circuit", .hash, .status, .signature, .activated_at, .activated_by, (.revoked_at // ""), (.revoked_by // ""), (.revocation_reason // "")] | @csv' "$CIRCUIT_REGISTRY" 2>/dev/null || true
            else
                echo "WARNING: jq not available, CSV export requires jq" >&2
            fi
            ;;
        *)
            echo "ERROR: Invalid format '$format'. Must be 'json' or 'csv'" >&2
            exit 2
            ;;
    esac
}

cmd_list() {
    local status_filter="all"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --status) status_filter="$2"; shift 2 ;;
            *) echo "ERROR: Unknown option for list: $1" >&2; exit 2 ;;
        esac
    done

    case "$status_filter" in
        active|revoked|all) ;;
        *) echo "ERROR: Invalid status '$status_filter'. Must be 'active', 'revoked', or 'all'" >&2; exit 2 ;;
    esac

    echo "=== Measurement Registry ==="
    if command -v jq &>/dev/null; then
        if [[ "$status_filter" == "all" ]]; then
            jq -r '.entries[] | "  [\(.status)] \(.hash) (activated: \(.activated_at))"' "$MEASUREMENT_REGISTRY" 2>/dev/null || echo "  (empty)"
        else
            jq -r --arg s "$status_filter" '.entries[] | select(.status == $s) | "  [\(.status)] \(.hash) (activated: \(.activated_at))"' "$MEASUREMENT_REGISTRY" 2>/dev/null || echo "  (empty)"
        fi
    else
        echo "  (jq required for formatted listing)"
        cat "$MEASUREMENT_REGISTRY"
    fi

    echo ""
    echo "=== Circuit Registry ==="
    if command -v jq &>/dev/null; then
        if [[ "$status_filter" == "all" ]]; then
            jq -r '.entries[] | "  [\(.status)] \(.hash) (activated: \(.activated_at))"' "$CIRCUIT_REGISTRY" 2>/dev/null || echo "  (empty)"
        else
            jq -r --arg s "$status_filter" '.entries[] | select(.status == $s) | "  [\(.status)] \(.hash) (activated: \(.activated_at))"' "$CIRCUIT_REGISTRY" 2>/dev/null || echo "  (empty)"
        fi
    else
        echo "  (jq required for formatted listing)"
        cat "$CIRCUIT_REGISTRY"
    fi

    # Summary
    echo ""
    if command -v jq &>/dev/null; then
        local m_active m_revoked c_active c_revoked
        m_active=$(jq '[.entries[] | select(.status == "active")] | length' "$MEASUREMENT_REGISTRY" 2>/dev/null || echo 0)
        m_revoked=$(jq '[.entries[] | select(.status == "revoked")] | length' "$MEASUREMENT_REGISTRY" 2>/dev/null || echo 0)
        c_active=$(jq '[.entries[] | select(.status == "active")] | length' "$CIRCUIT_REGISTRY" 2>/dev/null || echo 0)
        c_revoked=$(jq '[.entries[] | select(.status == "revoked")] | length' "$CIRCUIT_REGISTRY" 2>/dev/null || echo 0)
        echo "Summary: Measurements(active=$m_active, revoked=$m_revoked) Circuits(active=$c_active, revoked=$c_revoked)"
    fi
}

cmd_verify() {
    local hash=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --hash) hash="$2"; shift 2 ;;
            *) echo "ERROR: Unknown option for verify: $1" >&2; exit 2 ;;
        esac
    done

    if [[ -z "$hash" ]]; then
        echo "ERROR: verify requires --hash <hex>" >&2
        exit 2
    fi

    validate_hex "$hash" "hash"

    local found=false
    local entry_type=""
    local status=""

    # Check measurements
    if hash_exists "$MEASUREMENT_REGISTRY" "$hash"; then
        found=true
        entry_type="measurement"
        if hash_is_active "$MEASUREMENT_REGISTRY" "$hash"; then
            status="active"
        else
            status="revoked"
        fi
    fi

    # Check circuits
    if hash_exists "$CIRCUIT_REGISTRY" "$hash"; then
        found=true
        entry_type="circuit"
        if hash_is_active "$CIRCUIT_REGISTRY" "$hash"; then
            status="active"
        else
            status="revoked"
        fi
    fi

    if [[ "$found" == "false" ]]; then
        echo "NOT FOUND: Hash $hash is not in any registry"
        exit 1
    fi

    if [[ "$status" == "active" ]]; then
        echo "ACTIVE: Hash $hash is active in $entry_type registry"

        if command -v jq &>/dev/null; then
            local registry_file
            registry_file=$(get_registry_file "$entry_type")
            echo ""
            echo "Details:"
            jq --arg h "$hash" '.entries[] | select(.hash == $h)' "$registry_file"
        fi
        exit 0
    else
        echo "REVOKED: Hash $hash is revoked in $entry_type registry"

        if command -v jq &>/dev/null; then
            local registry_file
            registry_file=$(get_registry_file "$entry_type")
            echo ""
            echo "Details:"
            jq --arg h "$hash" '.entries[] | select(.hash == $h)' "$registry_file"
        fi
        exit 1
    fi
}

# ============================================================================
# Help
# ============================================================================

show_help() {
    head -35 "$0" | grep '^#' | sed 's/^# \?//'
}

# ============================================================================
# Main
# ============================================================================

main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 2
    fi

    local command="$1"
    shift

    init_registry

    case "$command" in
        activate) cmd_activate "$@" ;;
        revoke)   cmd_revoke "$@" ;;
        audit)    cmd_audit "$@" ;;
        export)   cmd_export "$@" ;;
        list)     cmd_list "$@" ;;
        verify)   cmd_verify "$@" ;;
        --help|-h|help)
            show_help
            exit 0
            ;;
        *)
            echo "ERROR: Unknown command '$command'" >&2
            echo "Run '$0 --help' for usage information" >&2
            exit 2
            ;;
    esac
}

main "$@"
