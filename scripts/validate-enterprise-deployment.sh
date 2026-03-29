#!/usr/bin/env bash
# validate-enterprise-deployment.sh
#
# Enterprise deployment validation for Aethelred L1.
# Checks all required services, TEE attestation, prover endpoints,
# and monitoring to produce a structured JSON report.
#
# Usage:
#   ./scripts/validate-enterprise-deployment.sh [options]
#
# Options:
#   --validator-rpc <host:port>   Validator RPC endpoint (default: localhost:26657)
#   --validator-grpc <host:port>  Validator gRPC endpoint (default: localhost:9090)
#   --tee-endpoint <host:port>    TEE worker gRPC endpoint (default: localhost:50051)
#   --attestation <host:port>     Attestation service endpoint (default: localhost:50052)
#   --prover-ezkl <host:port>     EZKL prover endpoint (default: localhost:50061)
#   --prover-risczero <host:port> RISC Zero prover endpoint (default: localhost:50062)
#   --prover-groth16 <host:port>  Groth16 prover endpoint (default: localhost:50063)
#   --bridge <host:port>          Bridge relayer endpoint (default: localhost:50081)
#   --prometheus <host:port>      Prometheus endpoint (default: localhost:9090)
#   --grafana <host:port>         Grafana endpoint (default: localhost:3000)
#   --loki <host:port>            Loki endpoint (default: localhost:3100)
#   --output <path>               Output JSON report path (default: stdout)
#   --topology <A|B|C>            Expected topology (default: A)
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

VALIDATOR_RPC="localhost:26657"
VALIDATOR_GRPC="localhost:9090"
TEE_ENDPOINT="localhost:50051"
ATTESTATION_ENDPOINT="localhost:50052"
PROVER_EZKL="localhost:50061"
PROVER_RISCZERO="localhost:50062"
PROVER_GROTH16="localhost:50063"
BRIDGE_ENDPOINT="localhost:50081"
PROMETHEUS_ENDPOINT="localhost:9090"
GRAFANA_ENDPOINT="localhost:3000"
LOKI_ENDPOINT="localhost:3100"
OUTPUT_PATH=""
TOPOLOGY="A"

# ============================================================================
# Parse arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --validator-rpc)   VALIDATOR_RPC="$2"; shift 2 ;;
        --validator-grpc)  VALIDATOR_GRPC="$2"; shift 2 ;;
        --tee-endpoint)    TEE_ENDPOINT="$2"; shift 2 ;;
        --attestation)     ATTESTATION_ENDPOINT="$2"; shift 2 ;;
        --prover-ezkl)     PROVER_EZKL="$2"; shift 2 ;;
        --prover-risczero) PROVER_RISCZERO="$2"; shift 2 ;;
        --prover-groth16)  PROVER_GROTH16="$2"; shift 2 ;;
        --bridge)          BRIDGE_ENDPOINT="$2"; shift 2 ;;
        --prometheus)      PROMETHEUS_ENDPOINT="$2"; shift 2 ;;
        --grafana)         GRAFANA_ENDPOINT="$2"; shift 2 ;;
        --loki)            LOKI_ENDPOINT="$2"; shift 2 ;;
        --output)          OUTPUT_PATH="$2"; shift 2 ;;
        --topology)        TOPOLOGY="$2"; shift 2 ;;
        --help)
            head -30 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# ============================================================================
# Minimum component counts by topology
# ============================================================================

case "$TOPOLOGY" in
    A) MIN_VALIDATORS=4; MIN_TEE=4; MIN_PROVERS=3; MIN_BRIDGE=1 ;;
    B) MIN_VALIDATORS=7; MIN_TEE=8; MIN_PROVERS=8; MIN_BRIDGE=2 ;;
    C) MIN_VALIDATORS=10; MIN_TEE=10; MIN_PROVERS=13; MIN_BRIDGE=3 ;;
    *)
        echo "ERROR: Invalid topology: $TOPOLOGY (must be A, B, or C)" >&2
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

# ============================================================================
# Helper functions
# ============================================================================

check_dependency() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        echo "WARNING: $cmd not found, some checks will be skipped" >&2
        return 1
    fi
    return 0
}

# Record a check result
# Usage: record_check <category> <name> <status> <message> [<details>]
record_check() {
    local category="$1"
    local name="$2"
    local status="$3"  # PASS, FAIL, WARN, SKIP
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

# Check if a TCP port is reachable
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

# Check HTTP endpoint returns expected status
check_http() {
    local url="$1"
    local expected_status="${2:-200}"
    local timeout=10

    if ! command -v curl &>/dev/null; then
        return 2
    fi

    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$timeout" "$url" 2>/dev/null || echo "000")

    if [[ "$status" == "$expected_status" ]]; then
        return 0
    else
        return 1
    fi
}

# Check gRPC endpoint health (using grpc_health_probe if available, else TCP check)
check_grpc() {
    local endpoint="$1"

    if command -v grpc_health_probe &>/dev/null; then
        grpc_health_probe -addr="$endpoint" -connect-timeout=5s 2>/dev/null
    else
        check_port "$endpoint"
    fi
}

# ============================================================================
# Validation checks
# ============================================================================

run_validator_checks() {
    local category="validator"

    # Check validator RPC is reachable
    if check_port "$VALIDATOR_RPC"; then
        record_check "$category" "rpc_reachable" "PASS" "Validator RPC endpoint is reachable" "$VALIDATOR_RPC"
    else
        record_check "$category" "rpc_reachable" "FAIL" "Validator RPC endpoint is not reachable" "$VALIDATOR_RPC"
        return
    fi

    # Check validator status via RPC
    if command -v curl &>/dev/null; then
        local status_resp
        status_resp=$(curl -s --max-time 10 "http://$VALIDATOR_RPC/status" 2>/dev/null || echo "{}")

        # Check if node is catching up
        local catching_up
        catching_up=$(echo "$status_resp" | grep -o '"catching_up":[a-z]*' | head -1 | cut -d: -f2 || echo "unknown")

        if [[ "$catching_up" == "false" ]]; then
            record_check "$category" "sync_status" "PASS" "Validator node is synced" "catching_up=false"
        elif [[ "$catching_up" == "true" ]]; then
            record_check "$category" "sync_status" "WARN" "Validator node is still catching up" "catching_up=true"
        else
            record_check "$category" "sync_status" "WARN" "Could not determine sync status" "Response parse failed"
        fi

        # Check latest block height
        local block_height
        block_height=$(echo "$status_resp" | grep -o '"latest_block_height":"[0-9]*"' | head -1 | grep -o '[0-9]*' || echo "0")

        if [[ "$block_height" -gt 0 ]]; then
            record_check "$category" "block_production" "PASS" "Validator is producing blocks" "height=$block_height"
        else
            record_check "$category" "block_production" "FAIL" "No blocks detected" "height=$block_height"
        fi

        # Check validator count via validators endpoint
        local val_resp
        val_resp=$(curl -s --max-time 10 "http://$VALIDATOR_RPC/validators" 2>/dev/null || echo "{}")
        local val_count
        val_count=$(echo "$val_resp" | grep -o '"total":"[0-9]*"' | head -1 | grep -o '[0-9]*' || echo "0")

        if [[ "$val_count" -ge "$MIN_VALIDATORS" ]]; then
            record_check "$category" "validator_count" "PASS" "Sufficient validators in active set" "count=$val_count, required=$MIN_VALIDATORS"
        else
            record_check "$category" "validator_count" "FAIL" "Insufficient validators in active set" "count=$val_count, required=$MIN_VALIDATORS"
        fi
    else
        record_check "$category" "status_check" "SKIP" "curl not available, skipping detailed validator checks" ""
    fi

    # Check gRPC endpoint
    if check_grpc "$VALIDATOR_GRPC"; then
        record_check "$category" "grpc_reachable" "PASS" "Validator gRPC endpoint is reachable" "$VALIDATOR_GRPC"
    else
        record_check "$category" "grpc_reachable" "FAIL" "Validator gRPC endpoint is not reachable" "$VALIDATOR_GRPC"
    fi
}

run_tee_checks() {
    local category="tee"

    # Check TEE worker endpoint
    if check_grpc "$TEE_ENDPOINT"; then
        record_check "$category" "worker_reachable" "PASS" "TEE worker endpoint is reachable" "$TEE_ENDPOINT"
    else
        record_check "$category" "worker_reachable" "FAIL" "TEE worker endpoint is not reachable" "$TEE_ENDPOINT"
    fi

    # Check attestation service
    if check_grpc "$ATTESTATION_ENDPOINT"; then
        record_check "$category" "attestation_reachable" "PASS" "Attestation service endpoint is reachable" "$ATTESTATION_ENDPOINT"
    else
        record_check "$category" "attestation_reachable" "FAIL" "Attestation service endpoint is not reachable" "$ATTESTATION_ENDPOINT"
    fi

    # Check SGX availability (if on SGX-capable host)
    if [[ -e /dev/sgx_enclave ]] || [[ -e /dev/isgx ]]; then
        record_check "$category" "sgx_device" "PASS" "SGX device node detected" "/dev/sgx_enclave or /dev/isgx present"
    else
        record_check "$category" "sgx_device" "WARN" "SGX device node not detected (may be running Nitro or non-SGX host)" "Neither /dev/sgx_enclave nor /dev/isgx found"
    fi

    # Check Nitro enclave (if nitro-cli available)
    if command -v nitro-cli &>/dev/null; then
        local enclave_info
        enclave_info=$(nitro-cli describe-enclaves 2>/dev/null || echo "[]")
        if [[ "$enclave_info" != "[]" ]] && echo "$enclave_info" | grep -q "RUNNING"; then
            record_check "$category" "nitro_enclave" "PASS" "Nitro enclave is running" ""
        else
            record_check "$category" "nitro_enclave" "FAIL" "No running Nitro enclaves detected" ""
        fi
    else
        record_check "$category" "nitro_enclave" "SKIP" "nitro-cli not available" ""
    fi

    # Check attestation validity via HTTP (if attestation service exposes HTTP health)
    if check_http "http://$ATTESTATION_ENDPOINT/health" "200" 2>/dev/null; then
        record_check "$category" "attestation_health" "PASS" "Attestation service health check passed" ""
    elif check_port "$ATTESTATION_ENDPOINT"; then
        record_check "$category" "attestation_health" "WARN" "Attestation port reachable but HTTP health check not available (gRPC-only is expected)" ""
    else
        record_check "$category" "attestation_health" "FAIL" "Attestation service not responding" "$ATTESTATION_ENDPOINT"
    fi
}

run_prover_checks() {
    local category="prover"

    # Check EZKL prover
    if check_grpc "$PROVER_EZKL"; then
        record_check "$category" "ezkl_reachable" "PASS" "EZKL prover endpoint is reachable" "$PROVER_EZKL"
    else
        record_check "$category" "ezkl_reachable" "FAIL" "EZKL prover endpoint is not reachable" "$PROVER_EZKL"
    fi

    # Check RISC Zero prover
    if check_grpc "$PROVER_RISCZERO"; then
        record_check "$category" "risczero_reachable" "PASS" "RISC Zero prover endpoint is reachable" "$PROVER_RISCZERO"
    else
        record_check "$category" "risczero_reachable" "FAIL" "RISC Zero prover endpoint is not reachable" "$PROVER_RISCZERO"
    fi

    # Check Groth16 prover
    if check_grpc "$PROVER_GROTH16"; then
        record_check "$category" "groth16_reachable" "PASS" "Groth16 prover endpoint is reachable" "$PROVER_GROTH16"
    else
        record_check "$category" "groth16_reachable" "FAIL" "Groth16 prover endpoint is not reachable" "$PROVER_GROTH16"
    fi
}

run_bridge_checks() {
    local category="bridge"

    # Check bridge relayer endpoint
    if check_grpc "$BRIDGE_ENDPOINT"; then
        record_check "$category" "relayer_reachable" "PASS" "Bridge relayer endpoint is reachable" "$BRIDGE_ENDPOINT"
    else
        record_check "$category" "relayer_reachable" "FAIL" "Bridge relayer endpoint is not reachable" "$BRIDGE_ENDPOINT"
    fi

    # Check bridge health via HTTP (if available)
    if check_http "http://$BRIDGE_ENDPOINT/health" "200" 2>/dev/null; then
        record_check "$category" "relayer_health" "PASS" "Bridge relayer health check passed" ""
    elif check_port "$BRIDGE_ENDPOINT"; then
        record_check "$category" "relayer_health" "WARN" "Bridge port reachable but HTTP health check not available" ""
    else
        record_check "$category" "relayer_health" "FAIL" "Bridge relayer not responding" "$BRIDGE_ENDPOINT"
    fi
}

run_monitoring_checks() {
    local category="monitoring"

    # Check Prometheus
    if check_http "http://$PROMETHEUS_ENDPOINT/-/healthy" "200"; then
        record_check "$category" "prometheus_healthy" "PASS" "Prometheus is healthy" "$PROMETHEUS_ENDPOINT"
    else
        record_check "$category" "prometheus_healthy" "FAIL" "Prometheus health check failed" "$PROMETHEUS_ENDPOINT"
    fi

    # Check Prometheus targets (look for down targets)
    if command -v curl &>/dev/null; then
        local targets_resp
        targets_resp=$(curl -s --max-time 10 "http://$PROMETHEUS_ENDPOINT/api/v1/targets" 2>/dev/null || echo "{}")
        local down_count
        down_count=$(echo "$targets_resp" | grep -o '"health":"down"' | wc -l | tr -d ' ' || echo "0")

        if [[ "$down_count" -eq 0 ]]; then
            record_check "$category" "prometheus_targets" "PASS" "All Prometheus targets are up" "down_count=0"
        else
            record_check "$category" "prometheus_targets" "WARN" "Some Prometheus targets are down" "down_count=$down_count"
        fi
    fi

    # Check Grafana
    if check_http "http://$GRAFANA_ENDPOINT/api/health" "200"; then
        record_check "$category" "grafana_healthy" "PASS" "Grafana is healthy" "$GRAFANA_ENDPOINT"
    else
        record_check "$category" "grafana_healthy" "FAIL" "Grafana health check failed" "$GRAFANA_ENDPOINT"
    fi

    # Check Loki
    if check_http "http://$LOKI_ENDPOINT/ready" "200"; then
        record_check "$category" "loki_ready" "PASS" "Loki is ready" "$LOKI_ENDPOINT"
    else
        record_check "$category" "loki_ready" "FAIL" "Loki readiness check failed" "$LOKI_ENDPOINT"
    fi
}

run_security_checks() {
    local category="security"

    # Check TLS on validator RPC
    if command -v openssl &>/dev/null; then
        local tls_host="${VALIDATOR_RPC%%:*}"
        local tls_port="${VALIDATOR_RPC##*:}"
        local tls_result
        tls_result=$(echo | openssl s_client -connect "$tls_host:$tls_port" -tls1_3 2>/dev/null | head -1 || echo "NONE")

        if echo "$tls_result" | grep -q "CONNECTED"; then
            record_check "$category" "tls_validator" "PASS" "TLS 1.3 connection to validator succeeded" ""
        else
            record_check "$category" "tls_validator" "WARN" "TLS 1.3 connection to validator failed (may be expected for localhost)" ""
        fi
    else
        record_check "$category" "tls_validator" "SKIP" "openssl not available" ""
    fi

    # Check disk encryption (Linux only)
    if command -v lsblk &>/dev/null; then
        local crypt_count
        crypt_count=$(lsblk -o TYPE 2>/dev/null | grep -c "crypt" || echo "0")
        if [[ "$crypt_count" -gt 0 ]]; then
            record_check "$category" "disk_encryption" "PASS" "LUKS encrypted volumes detected" "encrypted_volumes=$crypt_count"
        else
            record_check "$category" "disk_encryption" "WARN" "No LUKS encrypted volumes detected" "May use cloud-provider encryption"
        fi
    else
        record_check "$category" "disk_encryption" "SKIP" "lsblk not available (non-Linux platform)" ""
    fi

    # Check if SSH is disabled (production hardening)
    if check_port "localhost:22" 2>/dev/null; then
        record_check "$category" "ssh_disabled" "WARN" "SSH port 22 is open (should be disabled in production)" ""
    else
        record_check "$category" "ssh_disabled" "PASS" "SSH port 22 is not listening" ""
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

    # Build checks array
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
    "title": "Aethelred Enterprise Deployment Validation",
    "version": "1.0.0",
    "timestamp": "$TIMESTAMP",
    "topology": "$TOPOLOGY",
    "overall_status": "$overall_status"
  },
  "summary": {
    "total_checks": $total,
    "passed": $PASS_COUNT,
    "failed": $FAIL_COUNT,
    "warnings": $WARN_COUNT,
    "skipped": $SKIP_COUNT
  },
  "configuration": {
    "validator_rpc": "$VALIDATOR_RPC",
    "validator_grpc": "$VALIDATOR_GRPC",
    "tee_endpoint": "$TEE_ENDPOINT",
    "attestation_endpoint": "$ATTESTATION_ENDPOINT",
    "prover_ezkl": "$PROVER_EZKL",
    "prover_risczero": "$PROVER_RISCZERO",
    "prover_groth16": "$PROVER_GROTH16",
    "bridge_endpoint": "$BRIDGE_ENDPOINT",
    "prometheus": "$PROMETHEUS_ENDPOINT",
    "grafana": "$GRAFANA_ENDPOINT",
    "loki": "$LOKI_ENDPOINT"
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
    echo "=== Aethelred Enterprise Deployment Validation ===" >&2
    echo "Topology: $TOPOLOGY | Timestamp: $TIMESTAMP" >&2
    echo "" >&2

    echo "[1/6] Checking validator nodes..." >&2
    run_validator_checks

    echo "[2/6] Checking TEE workers and attestation..." >&2
    run_tee_checks

    echo "[3/6] Checking zkML provers..." >&2
    run_prover_checks

    echo "[4/6] Checking bridge relayer..." >&2
    run_bridge_checks

    echo "[5/6] Checking monitoring stack..." >&2
    run_monitoring_checks

    echo "[6/6] Running security checks..." >&2
    run_security_checks

    echo "" >&2
    echo "--- Results ---" >&2
    echo "PASS: $PASS_COUNT | FAIL: $FAIL_COUNT | WARN: $WARN_COUNT | SKIP: $SKIP_COUNT" >&2
    echo "" >&2

    generate_report

    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        echo "RESULT: FAIL -- $FAIL_COUNT check(s) failed" >&2
        exit 1
    else
        echo "RESULT: PASS -- All critical checks passed" >&2
        exit 0
    fi
}

main
