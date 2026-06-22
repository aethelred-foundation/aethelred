#!/usr/bin/env bash
# validate-pilot-deployment.sh
#
# Pilot deployment validation for Aethelred L1.
# Extends validate-enterprise-deployment.sh with pilot-specific checks:
#   - Workload pack configuration
#   - Pilot model registration (hash match)
#   - Pilot circuit registration
#   - Evidence export path writability
#   - Audit archive destination reachability
#   - Monitoring and alerting configuration
#
# Usage:
#   ./scripts/validate-pilot-deployment.sh [options]
#
# Options (inherits all enterprise deployment options, plus):
#   --workload-pack <path>        Workload pack config file (default: workload-pack.json)
#   --model-hash <hex>            Expected pilot model measurement hash
#   --circuit-hash <hex>          Expected pilot circuit hash
#   --evidence-path <dir>         Evidence export directory (default: /var/aethelred/evidence)
#   --archive-dest <host:port>    Audit archive destination (default: localhost:9200)
#   --archive-scheme <scheme>     Archive scheme: http or https (default: http)
#                                 https probes use -k for self-signed rehearsal certs and
#                                 read AETHELRED_ARCHIVE_USER / AETHELRED_ARCHIVE_PASSWORD
#                                 for basic auth when set.
#   --registry-dir <dir>          Registry data directory (default: ~/.aethelred/registry)
#   --alertmanager <host:port>    Alertmanager endpoint (default: localhost:9093)
#   --pilot-name <name>           Pilot deployment name (default: pilot-001)
#   --mode <mode>                 Validation mode: production or pre-testnet (default: production)
#   --pre-testnet                 Alias for --mode pre-testnet
#   --enterprise-script <path>    Path to enterprise validation script
#   --skip-enterprise             Skip enterprise validation (pilot-only checks)
#   --output <path>               Output JSON report path (default: stdout)
#   --help                        Show this help message
#
# Exit codes:
#   0 - All checks passed
#   1 - One or more checks failed
#   2 - Script error (invalid arguments, missing dependencies)

set -euo pipefail

# ============================================================================
# Configuration defaults
# ============================================================================

WORKLOAD_PACK="workload-pack.json"
MODEL_HASH=""
CIRCUIT_HASH=""
EVIDENCE_PATH="/var/aethelred/evidence"
ARCHIVE_DEST="localhost:9200"
ARCHIVE_SCHEME="http"
ARCHIVE_USER="${AETHELRED_ARCHIVE_USER:-admin}"
ARCHIVE_PASSWORD="${AETHELRED_ARCHIVE_PASSWORD:-}"
REGISTRY_DIR="${AETHELRED_REGISTRY_DIR:-$HOME/.aethelred/registry}"
ALERTMANAGER_ENDPOINT="localhost:9093"
PILOT_NAME="pilot-001"
VALIDATION_MODE="production"
ENTERPRISE_SCRIPT="$(dirname "$0")/validate-enterprise-deployment.sh"
SKIP_ENTERPRISE=false
OUTPUT_PATH=""

# Enterprise passthrough args
ENTERPRISE_ARGS=()

# ============================================================================
# Parse arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --workload-pack)    WORKLOAD_PACK="$2"; shift 2 ;;
        --model-hash)       MODEL_HASH="$2"; shift 2 ;;
        --circuit-hash)     CIRCUIT_HASH="$2"; shift 2 ;;
        --evidence-path)    EVIDENCE_PATH="$2"; shift 2 ;;
        --archive-dest)     ARCHIVE_DEST="$2"; shift 2 ;;
        --archive-scheme)   ARCHIVE_SCHEME="$2"; shift 2 ;;
        --registry-dir)     REGISTRY_DIR="$2"; shift 2 ;;
        --alertmanager)     ALERTMANAGER_ENDPOINT="$2"; shift 2 ;;
        --pilot-name)       PILOT_NAME="$2"; shift 2 ;;
        --mode)             VALIDATION_MODE="$2"; shift 2 ;;
        --pre-testnet)      VALIDATION_MODE="pre-testnet"; shift ;;
        --enterprise-script) ENTERPRISE_SCRIPT="$2"; shift 2 ;;
        --skip-enterprise)  SKIP_ENTERPRISE=true; shift ;;
        --output)           OUTPUT_PATH="$2"; shift 2 ;;
        --help)
            sed -n '1,/^set -euo pipefail/p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        # Pass through enterprise deployment options
        --validator-rpc|--validator-grpc|--tee-endpoint|--attestation|\
        --prover-ezkl|--prover-risczero|--prover-groth16|--bridge|\
        --prometheus|--grafana|--loki|--topology)
            ENTERPRISE_ARGS+=("$1" "$2"); shift 2 ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

case "$VALIDATION_MODE" in
    production|pre-testnet) ;;
    *)
        echo "ERROR: Invalid mode: $VALIDATION_MODE (must be production or pre-testnet)" >&2
        exit 2
        ;;
esac

case "$ARCHIVE_SCHEME" in
    http|https) ;;
    *)
        echo "ERROR: Invalid archive scheme: $ARCHIVE_SCHEME (must be http or https)" >&2
        exit 2
        ;;
esac

# ============================================================================
# Globals
# ============================================================================

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

MEASUREMENT_REGISTRY="$REGISTRY_DIR/measurements.json"
CIRCUIT_REGISTRY="$REGISTRY_DIR/circuits.json"

# ============================================================================
# Helper functions (same pattern as enterprise script)
# ============================================================================

record_check() {
    local category="$1"
    local name="$2"
    local status="$3"
    local message="$4"
    local details="${5:-}"

    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac

    local entry
    entry=$(cat <<ENTRY_EOF
    {
      "category": "$category",
      "name": "$name",
      "status": "$status",
      "message": "$message",
      "details": "$details",
      "timestamp": "$TIMESTAMP"
    }
ENTRY_EOF
)
    RESULTS+=("$entry")
}

check_port() {
    local host_port="$1"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    local timeout=5

    if command -v nc &>/dev/null; then
        nc -z -w "$timeout" "$host" "$port" 2>/dev/null
    elif command -v bash &>/dev/null; then
        timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    else
        return 1
    fi
}

check_http() {
    local url="$1"
    local expected_status="${2:-200}"
    local timeout=10

    if ! command -v curl &>/dev/null; then
        return 2
    fi

    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$timeout" "$url" 2>/dev/null || echo "000")
    [[ "$status" == "$expected_status" ]]
}

is_pre_testnet_mode() {
    [[ "$VALIDATION_MODE" == "pre-testnet" ]]
}

# ============================================================================
# Pilot-specific checks
# ============================================================================

run_workload_pack_checks() {
    local category="pilot_workload"

    # Check workload pack file exists
    if [[ -f "$WORKLOAD_PACK" ]]; then
        record_check "$category" "pack_exists" "PASS" "Workload pack config file exists" "$WORKLOAD_PACK"
    elif is_pre_testnet_mode; then
        record_check "$category" "pack_exists" "WARN" "Workload pack config file not found; required before testnet or production pilot promotion" "$WORKLOAD_PACK"
        return
    else
        record_check "$category" "pack_exists" "FAIL" "Workload pack config file not found" "$WORKLOAD_PACK"
        return
    fi

    # Check workload pack is valid JSON
    if command -v jq &>/dev/null; then
        if jq empty "$WORKLOAD_PACK" 2>/dev/null; then
            record_check "$category" "pack_valid_json" "PASS" "Workload pack is valid JSON" ""
        else
            record_check "$category" "pack_valid_json" "FAIL" "Workload pack is not valid JSON" "$WORKLOAD_PACK"
            return
        fi

        # Check required fields
        local required_fields=("name" "version" "model" "circuit")
        for field in "${required_fields[@]}"; do
            if jq -e ".$field" "$WORKLOAD_PACK" >/dev/null 2>&1; then
                record_check "$category" "pack_field_$field" "PASS" "Workload pack has required field '$field'" ""
            else
                record_check "$category" "pack_field_$field" "FAIL" "Workload pack missing required field '$field'" ""
            fi
        done

        # Check model hash in pack matches expected
        if [[ -n "$MODEL_HASH" ]]; then
            local pack_model_hash
            pack_model_hash=$(jq -r '.model.hash // .model.measurement_hash // ""' "$WORKLOAD_PACK" 2>/dev/null || echo "")
            if [[ "$pack_model_hash" == "$MODEL_HASH" ]]; then
                record_check "$category" "pack_model_hash_match" "PASS" "Workload pack model hash matches expected" "expected=$MODEL_HASH"
            else
                record_check "$category" "pack_model_hash_match" "FAIL" "Workload pack model hash mismatch" "expected=$MODEL_HASH, got=$pack_model_hash"
            fi
        fi

        # Check circuit hash in pack matches expected
        if [[ -n "$CIRCUIT_HASH" ]]; then
            local pack_circuit_hash
            pack_circuit_hash=$(jq -r '.circuit.hash // .circuit.circuit_hash // ""' "$WORKLOAD_PACK" 2>/dev/null || echo "")
            if [[ "$pack_circuit_hash" == "$CIRCUIT_HASH" ]]; then
                record_check "$category" "pack_circuit_hash_match" "PASS" "Workload pack circuit hash matches expected" "expected=$CIRCUIT_HASH"
            else
                record_check "$category" "pack_circuit_hash_match" "FAIL" "Workload pack circuit hash mismatch" "expected=$CIRCUIT_HASH, got=$pack_circuit_hash"
            fi
        fi
    else
        record_check "$category" "pack_validation" "SKIP" "jq not available, skipping detailed pack validation" ""
    fi
}

run_model_registration_checks() {
    local category="pilot_model"

    if [[ -z "$MODEL_HASH" ]]; then
        record_check "$category" "model_hash_provided" "SKIP" "No model hash specified (--model-hash)" ""
        return
    fi

    # Check registry exists
    if [[ ! -f "$MEASUREMENT_REGISTRY" ]]; then
        record_check "$category" "registry_exists" "FAIL" "Measurement registry not found" "$MEASUREMENT_REGISTRY"
        return
    fi

    record_check "$category" "registry_exists" "PASS" "Measurement registry exists" "$MEASUREMENT_REGISTRY"

    # Check model hash is registered and active
    if command -v jq &>/dev/null; then
        local entry
        entry=$(jq --arg h "$MODEL_HASH" '.entries[] | select(.hash == $h)' "$MEASUREMENT_REGISTRY" 2>/dev/null || echo "")

        if [[ -z "$entry" ]]; then
            record_check "$category" "model_registered" "FAIL" "Pilot model hash not found in measurement registry" "hash=$MODEL_HASH"
            return
        fi

        record_check "$category" "model_registered" "PASS" "Pilot model hash is registered" "hash=$MODEL_HASH"

        local model_status
        model_status=$(echo "$entry" | jq -r '.status' 2>/dev/null || echo "unknown")

        if [[ "$model_status" == "active" ]]; then
            record_check "$category" "model_active" "PASS" "Pilot model is active in registry" "hash=$MODEL_HASH"
        else
            record_check "$category" "model_active" "FAIL" "Pilot model is NOT active (status=$model_status)" "hash=$MODEL_HASH"
        fi
    else
        if grep -q "\"$MODEL_HASH\"" "$MEASUREMENT_REGISTRY" 2>/dev/null; then
            record_check "$category" "model_registered" "PASS" "Pilot model hash found in measurement registry" "hash=$MODEL_HASH"
        else
            record_check "$category" "model_registered" "FAIL" "Pilot model hash not found in measurement registry" "hash=$MODEL_HASH"
        fi
    fi
}

run_circuit_registration_checks() {
    local category="pilot_circuit"

    if [[ -z "$CIRCUIT_HASH" ]]; then
        record_check "$category" "circuit_hash_provided" "SKIP" "No circuit hash specified (--circuit-hash)" ""
        return
    fi

    # Check registry exists
    if [[ ! -f "$CIRCUIT_REGISTRY" ]]; then
        record_check "$category" "registry_exists" "FAIL" "Circuit registry not found" "$CIRCUIT_REGISTRY"
        return
    fi

    record_check "$category" "registry_exists" "PASS" "Circuit registry exists" "$CIRCUIT_REGISTRY"

    # Check circuit hash is registered and active
    if command -v jq &>/dev/null; then
        local entry
        entry=$(jq --arg h "$CIRCUIT_HASH" '.entries[] | select(.hash == $h)' "$CIRCUIT_REGISTRY" 2>/dev/null || echo "")

        if [[ -z "$entry" ]]; then
            record_check "$category" "circuit_registered" "FAIL" "Pilot circuit hash not found in circuit registry" "hash=$CIRCUIT_HASH"
            return
        fi

        record_check "$category" "circuit_registered" "PASS" "Pilot circuit hash is registered" "hash=$CIRCUIT_HASH"

        local circuit_status
        circuit_status=$(echo "$entry" | jq -r '.status' 2>/dev/null || echo "unknown")

        if [[ "$circuit_status" == "active" ]]; then
            record_check "$category" "circuit_active" "PASS" "Pilot circuit is active in registry" "hash=$CIRCUIT_HASH"
        else
            record_check "$category" "circuit_active" "FAIL" "Pilot circuit is NOT active (status=$circuit_status)" "hash=$CIRCUIT_HASH"
        fi
    else
        if grep -q "\"$CIRCUIT_HASH\"" "$CIRCUIT_REGISTRY" 2>/dev/null; then
            record_check "$category" "circuit_registered" "PASS" "Pilot circuit hash found in circuit registry" "hash=$CIRCUIT_HASH"
        else
            record_check "$category" "circuit_registered" "FAIL" "Pilot circuit hash not found in circuit registry" "hash=$CIRCUIT_HASH"
        fi
    fi
}

run_evidence_export_checks() {
    local category="pilot_evidence"

    # Check evidence directory exists
    if [[ -d "$EVIDENCE_PATH" ]]; then
        record_check "$category" "dir_exists" "PASS" "Evidence export directory exists" "$EVIDENCE_PATH"
    else
        record_check "$category" "dir_exists" "FAIL" "Evidence export directory does not exist" "$EVIDENCE_PATH"
        return
    fi

    # Check evidence directory is writable
    if [[ -w "$EVIDENCE_PATH" ]]; then
        record_check "$category" "dir_writable" "PASS" "Evidence export directory is writable" "$EVIDENCE_PATH"
    else
        record_check "$category" "dir_writable" "FAIL" "Evidence export directory is NOT writable" "$EVIDENCE_PATH"
    fi

    # Check available disk space (warn if < 10GB)
    if command -v df &>/dev/null; then
        local avail_kb
        avail_kb=$(df -k "$EVIDENCE_PATH" 2>/dev/null | tail -1 | awk '{print $4}' || echo "0")
        local avail_gb=$(( avail_kb / 1024 / 1024 ))

        if [[ "$avail_gb" -ge 10 ]]; then
            record_check "$category" "disk_space" "PASS" "Sufficient disk space for evidence" "available=${avail_gb}GB"
        elif [[ "$avail_gb" -ge 1 ]]; then
            record_check "$category" "disk_space" "WARN" "Low disk space for evidence" "available=${avail_gb}GB (recommend >=10GB)"
        else
            record_check "$category" "disk_space" "FAIL" "Critically low disk space for evidence" "available=${avail_gb}GB"
        fi
    else
        record_check "$category" "disk_space" "SKIP" "df not available, cannot check disk space" ""
    fi

    # Check evidence subdirectory structure
    local subdirs=("attestations" "proofs" "exports" "archives")
    for subdir in "${subdirs[@]}"; do
        if [[ -d "$EVIDENCE_PATH/$subdir" ]]; then
            record_check "$category" "subdir_$subdir" "PASS" "Evidence subdirectory '$subdir' exists" "$EVIDENCE_PATH/$subdir"
        else
            record_check "$category" "subdir_$subdir" "WARN" "Evidence subdirectory '$subdir' missing (will be created)" "$EVIDENCE_PATH/$subdir"
        fi
    done
}

run_archive_checks() {
    local category="pilot_archive"

    local archive_host="${ARCHIVE_DEST%%:*}"
    local archive_port="${ARCHIVE_DEST##*:}"

    # Check archive destination is reachable
    if check_port "$ARCHIVE_DEST"; then
        record_check "$category" "dest_reachable" "PASS" "Audit archive destination is reachable" "$ARCHIVE_DEST"
    elif is_pre_testnet_mode; then
        record_check "$category" "dest_reachable" "WARN" "Audit archive destination is not reachable; explicit preflight requirement before testnet or production pilot promotion" "$ARCHIVE_DEST"
        return
    else
        record_check "$category" "dest_reachable" "FAIL" "Audit archive destination is NOT reachable" "$ARCHIVE_DEST"
        return
    fi

    # Check archive endpoint health (assuming Elasticsearch/OpenSearch).
    # Secured archives (https + basic auth) are probed with the configured
    # credentials; self-signed rehearsal certificates are accepted with -k.
    local archive_curl_args=(-s -o /dev/null -w '%{http_code}' --max-time 10)
    if [[ "$ARCHIVE_SCHEME" == "https" ]]; then
        archive_curl_args+=(-k)
    fi
    if [[ -n "$ARCHIVE_PASSWORD" ]]; then
        archive_curl_args+=(-u "$ARCHIVE_USER:$ARCHIVE_PASSWORD")
    fi

    local archive_http_status="000"
    if command -v curl &>/dev/null; then
        archive_http_status=$(curl "${archive_curl_args[@]}" "$ARCHIVE_SCHEME://$ARCHIVE_DEST/_cluster/health" 2>/dev/null || echo "000")
    fi

    if [[ "$archive_http_status" == "200" ]]; then
        record_check "$category" "cluster_healthy" "PASS" "Archive cluster is healthy" "$ARCHIVE_SCHEME://$ARCHIVE_DEST"

        # Secured archives must reject anonymous access.
        if [[ -n "$ARCHIVE_PASSWORD" ]]; then
            local unauth_status
            unauth_status=$(curl -ks -o /dev/null -w '%{http_code}' --max-time 10 "$ARCHIVE_SCHEME://$ARCHIVE_DEST/_cluster/health" 2>/dev/null || echo "000")
            if [[ "$unauth_status" == "401" || "$unauth_status" == "403" ]]; then
                record_check "$category" "auth_enforced" "PASS" "Archive rejects unauthenticated access (HTTP $unauth_status)" "$ARCHIVE_SCHEME://$ARCHIVE_DEST"
            else
                record_check "$category" "auth_enforced" "FAIL" "Archive accepted or mishandled an unauthenticated request (HTTP $unauth_status); evidence archive must require authentication" "$ARCHIVE_SCHEME://$ARCHIVE_DEST"
            fi
        fi

        # Check for aethelred index
        local index_check
        index_check=$(curl "${archive_curl_args[@]}" "$ARCHIVE_SCHEME://$ARCHIVE_DEST/aethelred-evidence-*" 2>/dev/null || echo "000")
        if [[ "$index_check" == "200" ]]; then
            record_check "$category" "evidence_index" "PASS" "Archive evidence index exists" ""
        else
            record_check "$category" "evidence_index" "WARN" "Archive evidence index not found (will be created on first write)" ""
        fi
    elif [[ "$archive_http_status" == "401" || "$archive_http_status" == "403" ]]; then
        record_check "$category" "cluster_healthy" "FAIL" "Archive requires authentication (HTTP $archive_http_status); set AETHELRED_ARCHIVE_USER/AETHELRED_ARCHIVE_PASSWORD and --archive-scheme" "$ARCHIVE_SCHEME://$ARCHIVE_DEST"
    elif check_http "$ARCHIVE_SCHEME://$ARCHIVE_DEST/health" "200" 2>/dev/null; then
        record_check "$category" "cluster_healthy" "PASS" "Archive service health check passed" ""
    else
        record_check "$category" "cluster_healthy" "WARN" "Archive reachable but health endpoint not responding (may be non-standard)" "$ARCHIVE_SCHEME://$ARCHIVE_DEST"
    fi
}

run_monitoring_alerting_checks() {
    local category="pilot_monitoring"

    # Check Alertmanager
    if check_http "http://$ALERTMANAGER_ENDPOINT/-/healthy" "200" 2>/dev/null; then
        record_check "$category" "alertmanager_healthy" "PASS" "Alertmanager is healthy" "$ALERTMANAGER_ENDPOINT"
    elif check_port "$ALERTMANAGER_ENDPOINT"; then
        record_check "$category" "alertmanager_healthy" "WARN" "Alertmanager port reachable but health check failed" "$ALERTMANAGER_ENDPOINT"
    elif is_pre_testnet_mode; then
        record_check "$category" "alertmanager_healthy" "WARN" "Alertmanager is not reachable; explicit preflight requirement before testnet or production pilot promotion" "$ALERTMANAGER_ENDPOINT"
    else
        record_check "$category" "alertmanager_healthy" "FAIL" "Alertmanager is not reachable" "$ALERTMANAGER_ENDPOINT"
    fi

    # Check alert rules are configured
    if command -v curl &>/dev/null; then
        # Query Alertmanager for silences/alerts to confirm it is operational
        local alerts_resp
        alerts_resp=$(curl -s --max-time 10 "http://$ALERTMANAGER_ENDPOINT/api/v2/alerts" 2>/dev/null || echo "")
        if [[ -n "$alerts_resp" ]]; then
            record_check "$category" "alertmanager_api" "PASS" "Alertmanager API is responding" ""
        elif is_pre_testnet_mode; then
            record_check "$category" "alertmanager_api" "WARN" "Alertmanager API not responding; explicit preflight requirement before testnet or production pilot promotion" "$ALERTMANAGER_ENDPOINT"
        else
            record_check "$category" "alertmanager_api" "WARN" "Alertmanager API not responding" ""
        fi
    fi

    # Check for pilot-specific alert rules (via Prometheus)
    local PROMETHEUS_ENDPOINT="localhost:9090"
    local prom_next=false
    for ep_arg in "${ENTERPRISE_ARGS[@]+"${ENTERPRISE_ARGS[@]}"}"; do
        if [[ "$ep_arg" == "--prometheus" ]]; then
            prom_next=true
            continue
        fi
        if [[ "$prom_next" == "true" ]]; then
            PROMETHEUS_ENDPOINT="$ep_arg"
            prom_next=false
        fi
    done

    if command -v curl &>/dev/null; then
        local rules_resp
        rules_resp=$(curl -s --max-time 10 "http://$PROMETHEUS_ENDPOINT/api/v1/rules" 2>/dev/null || echo "")

        if echo "$rules_resp" | grep -qi "aethelred\|tee\|attestation\|zkml\|pouw" 2>/dev/null; then
            record_check "$category" "alert_rules_configured" "PASS" "Pilot-relevant alert rules detected in Prometheus" ""
        elif [[ -n "$rules_resp" ]]; then
            record_check "$category" "alert_rules_configured" "WARN" "Prometheus rules loaded but no pilot-specific rules detected" ""
        elif is_pre_testnet_mode; then
            record_check "$category" "alert_rules_configured" "WARN" "Could not query Prometheus rules; explicit preflight requirement before testnet or production pilot promotion" "$PROMETHEUS_ENDPOINT"
        else
            record_check "$category" "alert_rules_configured" "WARN" "Could not query Prometheus rules" "$PROMETHEUS_ENDPOINT"
        fi
    else
        record_check "$category" "alert_rules_configured" "SKIP" "curl not available" ""
    fi
}

# ============================================================================
# Generate JSON report
# ============================================================================

generate_report() {
    local total=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))
    local overall_status="PASS"
    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        overall_status="FAIL"
    elif [[ "$WARN_COUNT" -gt 0 ]]; then
        overall_status="WARN"
    fi

    local checks_json=""
    for i in "${!RESULTS[@]}"; do
        if [[ $i -gt 0 ]]; then
            checks_json="$checks_json,"
        fi
        checks_json="$checks_json
${RESULTS[$i]}"
    done

    local report
    report=$(cat <<REPORT_EOF
{
  "report": {
    "title": "Aethelred Pilot Deployment Validation",
    "version": "1.0.0",
    "timestamp": "$TIMESTAMP",
    "pilot_name": "$PILOT_NAME",
    "overall_status": "$overall_status"
  },
  "summary": {
    "total_checks": $total,
    "passed": $PASS_COUNT,
    "failed": $FAIL_COUNT,
    "warnings": $WARN_COUNT,
    "skipped": $SKIP_COUNT
  },
  "pilot_configuration": {
    "mode": "$VALIDATION_MODE",
    "workload_pack": "$WORKLOAD_PACK",
    "model_hash": "$MODEL_HASH",
    "circuit_hash": "$CIRCUIT_HASH",
    "evidence_path": "$EVIDENCE_PATH",
    "archive_dest": "$ARCHIVE_DEST",
    "archive_scheme": "$ARCHIVE_SCHEME",
    "registry_dir": "$REGISTRY_DIR",
    "alertmanager": "$ALERTMANAGER_ENDPOINT"
  },
  "checks": [$checks_json
  ]
}
REPORT_EOF
)

    if [[ -n "$OUTPUT_PATH" ]]; then
        mkdir -p "$(dirname "$OUTPUT_PATH")"
        echo "$report" > "$OUTPUT_PATH"
        echo "Report written to: $OUTPUT_PATH" >&2
    else
        echo "$report"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo "=== Aethelred Pilot Deployment Validation ===" >&2
    echo "Pilot: $PILOT_NAME | Mode: $VALIDATION_MODE | Timestamp: $TIMESTAMP" >&2
    if is_pre_testnet_mode; then
        echo "Pre-testnet mode keeps local evidence checks strict while reporting archive, monitoring, and workload-pack launch gates as warnings." >&2
    fi
    echo "" >&2

    # Step 1: Run enterprise validation (unless skipped)
    if [[ "$SKIP_ENTERPRISE" == "false" ]]; then
        echo "[0/6] Running enterprise baseline validation..." >&2
        if [[ -x "$ENTERPRISE_SCRIPT" ]]; then
            local enterprise_output
            enterprise_output=$("$ENTERPRISE_SCRIPT" "${ENTERPRISE_ARGS[@]+"${ENTERPRISE_ARGS[@]}"}" 2>/dev/null || true)
            # Check if enterprise validation passed
            if echo "$enterprise_output" | grep -q '"overall_status": "FAIL"' 2>/dev/null; then
                record_check "enterprise_baseline" "enterprise_validation" "FAIL" "Enterprise baseline validation failed" "Run validate-enterprise-deployment.sh for details"
            else
                record_check "enterprise_baseline" "enterprise_validation" "PASS" "Enterprise baseline validation passed" ""
            fi
        else
            record_check "enterprise_baseline" "enterprise_validation" "SKIP" "Enterprise validation script not found or not executable" "$ENTERPRISE_SCRIPT"
        fi
    else
        echo "[0/6] Skipping enterprise baseline validation..." >&2
        record_check "enterprise_baseline" "enterprise_validation" "SKIP" "Enterprise validation skipped (--skip-enterprise)" ""
    fi

    echo "[1/6] Checking workload pack configuration..." >&2
    run_workload_pack_checks

    echo "[2/6] Checking pilot model registration..." >&2
    run_model_registration_checks

    echo "[3/6] Checking pilot circuit registration..." >&2
    run_circuit_registration_checks

    echo "[4/6] Checking evidence export path..." >&2
    run_evidence_export_checks

    echo "[5/6] Checking audit archive destination..." >&2
    run_archive_checks

    echo "[6/6] Checking monitoring and alerting..." >&2
    run_monitoring_alerting_checks

    echo "" >&2
    echo "--- Pilot Validation Results ---" >&2
    echo "PASS: $PASS_COUNT | FAIL: $FAIL_COUNT | WARN: $WARN_COUNT | SKIP: $SKIP_COUNT" >&2
    echo "" >&2

    generate_report

    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        echo "RESULT: FAIL -- $FAIL_COUNT pilot check(s) failed" >&2
        exit 1
    elif [[ "$WARN_COUNT" -gt 0 ]]; then
        echo "RESULT: WARN -- no failed checks; $WARN_COUNT warning(s) require follow-up" >&2
        exit 0
    else
        echo "RESULT: PASS -- All pilot checks passed" >&2
        exit 0
    fi
}

main
