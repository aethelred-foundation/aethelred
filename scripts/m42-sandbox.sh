#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/integrations/docker/docker-compose.m42-pilot.yml"
SANDBOX_ENV="$ROOT_DIR/config/pilots/m42/sandbox.env"
IMAGES_LOCK="$ROOT_DIR/config/pilots/m42/images.lock.env"
SECRETS_DIR="$ROOT_DIR/config/pilots/m42/secrets"
ARCHIVE_SECRET_FILE="$SECRETS_DIR/opensearch_admin_password.txt"
REPORT_DIR="$ROOT_DIR/.cache/m42-pilot-evidence/exports"
SIMULATION_WAIVER="$ROOT_DIR/config/pilots/m42/waivers/simulated-go-live-waiver.json"

# Digest lock first so explicit operator overrides in sandbox.env win.
if [[ -f "$IMAGES_LOCK" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$IMAGES_LOCK"
    set +a
fi

if [[ -f "$SANDBOX_ENV" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$SANDBOX_ENV"
    set +a
fi

PROJECT_NAME="${M42_SANDBOX_PROJECT:-aethelred-m42-pilot}"
WORKLOAD_PACK="$ROOT_DIR/config/pilots/m42/workload-pack.json"
REGISTRY_DIR="$ROOT_DIR/config/pilots/m42/registry"
EVIDENCE_PATH="$ROOT_DIR/config/pilots/m42/evidence"

MODEL_HASH="$(jq -r '.model.hash' "$WORKLOAD_PACK")"
CIRCUIT_HASH="$(jq -r '.circuit.hash' "$WORKLOAD_PACK")"

VALIDATOR_RPC="${M42_VALIDATOR_RPC:-localhost:36657}"
VALIDATOR_GRPC="${M42_VALIDATOR_GRPC:-localhost:39090}"
TEE_ENDPOINT="${M42_TEE_ENDPOINT:-localhost:18545}"
ATTESTATION_ENDPOINT="${M42_ATTESTATION_ENDPOINT:-$TEE_ENDPOINT}"
ZKML_PROVER="${M42_ZKML_PROVER:-localhost:18546}"
BRIDGE_ENDPOINT="${M42_BRIDGE_ENDPOINT:-localhost:0}"
ARCHIVE_DEST="${M42_ARCHIVE_DEST:-localhost:19200}"
ARCHIVE_SCHEME="${M42_ARCHIVE_SCHEME:-https}"
ARCHIVE_USER="${M42_ARCHIVE_USER:-admin}"
PROMETHEUS_ENDPOINT="${M42_PROMETHEUS_ENDPOINT:-localhost:19090}"
ALERTMANAGER_ENDPOINT="${M42_ALERTMANAGER_ENDPOINT:-localhost:19093}"
GRAFANA_ENDPOINT="${M42_GRAFANA_ENDPOINT:-localhost:13001}"

usage() {
    cat <<USAGE
Usage: scripts/m42-sandbox.sh <command>

Commands:
  prepare         Create local evidence and secret directories
  up              Start the dedicated M42 sandbox
  down            Stop the dedicated M42 sandbox
  status          Show sandbox service status
  logs [service]  Stream sandbox logs
  config          Render Docker Compose config
  pin-images      Resolve image digests into config/pilots/m42/images.lock.env
  preflight       Validate package/docs without requiring live services
  drill           Generate pre-testnet evidence/value drill artifacts (active workload)
  drill-all       Generate drill evidence for all four workloads + catalog scorecard
  gap-audit       Generate investor-grade M42 gap register and sponsor portal
  gap-audit-strict Generate gap register and fail if any open blocker remains
  validate        Validate package and require live sandbox endpoints

Selected workload: m42-med42-synthetic-eval (Med42 synthetic clinical AI)
Compose file:      integrations/docker/docker-compose.m42-pilot.yml
USAGE
}

export_archive_secret() {
    if [[ -z "${M42_ARCHIVE_ADMIN_PASSWORD:-}" && -f "$ARCHIVE_SECRET_FILE" ]]; then
        M42_ARCHIVE_ADMIN_PASSWORD="$(tr -d '\n' < "$ARCHIVE_SECRET_FILE")"
        export M42_ARCHIVE_ADMIN_PASSWORD
    fi
}

compose() {
    export_archive_secret
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
        return
    fi
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
        return
    fi
    echo "Docker Compose is required for M42 sandbox command '$1'." >&2
    exit 2
}

ensure_secret() {
    local secret_file="$1"
    local current_secret=""

    if [[ -f "$secret_file" ]]; then
        current_secret="$(tr -d '\n' < "$secret_file")"
    fi

    if [[ ! -f "$secret_file" || "$current_secret" == *change-before* || "$current_secret" == *changeme* || ${#current_secret} -lt 24 ]]; then
        if command -v openssl >/dev/null 2>&1; then
            openssl rand -base64 32 > "$secret_file"
        else
            LC_ALL=C tr -dc 'A-Za-z0-9_=-' < /dev/urandom | head -c 40 > "$secret_file"
            printf '\n' >> "$secret_file"
        fi
        chmod 600 "$secret_file"
    fi
}

prepare() {
    mkdir -p \
        "$EVIDENCE_PATH/attestations" \
        "$EVIDENCE_PATH/proofs" \
        "$EVIDENCE_PATH/exports" \
        "$EVIDENCE_PATH/archives" \
        "$REPORT_DIR" \
        "$SECRETS_DIR"

    ensure_secret "$SECRETS_DIR/grafana_admin_password.txt"
    ensure_secret "$ARCHIVE_SECRET_FILE"
}

check_http() {
    local name="$1"
    local url="$2"
    if curl -fsS --max-time 10 "$url" >/dev/null 2>&1; then
        echo "[PASS] $name $url"
    else
        echo "[FAIL] $name $url" >&2
        return 1
    fi
}

check_archive() {
    local url="$ARCHIVE_SCHEME://$ARCHIVE_DEST/_cluster/health"
    export_archive_secret

    local curl_args=(-fsS --max-time 10)
    if [[ "$ARCHIVE_SCHEME" == "https" ]]; then
        # Loopback rehearsal archive uses the OpenSearch demo certificate.
        curl_args+=(-k)
    fi
    if [[ -n "${M42_ARCHIVE_ADMIN_PASSWORD:-}" ]]; then
        curl_args+=(-u "$ARCHIVE_USER:$M42_ARCHIVE_ADMIN_PASSWORD")
    fi

    if curl "${curl_args[@]}" "$url" >/dev/null 2>&1; then
        echo "[PASS] archive $url (authenticated)"
    else
        echo "[FAIL] archive $url" >&2
        return 1
    fi

    # The paid-pilot security assertion: anonymous access must be rejected.
    local unauth_status
    unauth_status="$(curl -ksS -o /dev/null -w '%{http_code}' --max-time 10 "$url" 2>/dev/null || echo 000)"
    if [[ "$unauth_status" == "401" || "$unauth_status" == "403" ]]; then
        echo "[PASS] archive rejects unauthenticated access (HTTP $unauth_status)"
    else
        echo "[FAIL] archive must reject unauthenticated access; got HTTP $unauth_status" >&2
        return 1
    fi
}

ref_repo() {
    local ref="${1%%@*}"
    local last_segment="${ref##*/}"
    if [[ "$last_segment" == *:* ]]; then
        printf '%s' "${ref%:*}"
    else
        printf '%s' "$ref"
    fi
}

resolve_digest() {
    local ref="$1"
    local raw=""

    # A registry digest is the sha256 of the raw manifest bytes.
    if docker buildx version >/dev/null 2>&1 && raw="$(docker buildx imagetools inspect --raw "$ref" 2>/dev/null)" && [[ -n "$raw" ]]; then
        if command -v sha256sum >/dev/null 2>&1; then
            printf 'sha256:%s' "$(printf '%s' "$raw" | sha256sum | cut -d' ' -f1)"
        else
            printf 'sha256:%s' "$(printf '%s' "$raw" | shasum -a 256 | cut -d' ' -f1)"
        fi
        return 0
    fi

    # Fall back to a local repo digest when the image was pulled or pushed.
    local repo_digest
    repo_digest="$(docker image inspect --format '{{join .RepoDigests "\n"}}' "$ref" 2>/dev/null | head -n 1 || true)"
    if [[ "$repo_digest" == *@sha256:* ]]; then
        printf '%s' "${repo_digest##*@}"
        return 0
    fi
    return 1
}

pin_images() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker is required to resolve image digests for pin-images." >&2
        exit 2
    fi

    local tmp_lock="${IMAGES_LOCK}.tmp"
    {
        echo "# M42 sandbox image digest lock."
        echo "# Generated by scripts/m42-sandbox.sh pin-images at $(date -u +%Y-%m-%dT%H:%M:%SZ)."
        echo "# Sourced automatically before compose/audit; regenerate after image updates."
    } > "$tmp_lock"

    local failures=0
    local line var ref repo digest
    while IFS= read -r line; do
        var="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*image:[[:space:]]*\$\{([A-Z0-9_]+):-.*/\1/')"
        ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*image:[[:space:]]*\$\{[A-Z0-9_]+:-(.+)\}[[:space:]]*$/\1/')"
        # Respect an operator override already present in the environment.
        eval "ref=\"\${$var:-$ref}\""
        if digest="$(resolve_digest "$ref")"; then
            repo="$(ref_repo "$ref")"
            echo "$var=$repo@$digest" >> "$tmp_lock"
            echo "[PINNED] $var $repo@$digest"
        else
            failures=1
            echo "[UNPINNED] $var $ref (no registry digest; push/pull the image, then rerun)" >&2
        fi
    done < <(grep -E '^[[:space:]]+image:[[:space:]]+\$\{M42_[A-Z0-9_]+_IMAGE:-' "$COMPOSE_FILE")

    mv "$tmp_lock" "$IMAGES_LOCK"
    echo "Wrote $IMAGES_LOCK"
    if [[ "$failures" -ne 0 ]]; then
        echo "Some images could not be digest pinned. The strict go-live gate stays closed until every image resolves." >&2
        exit 1
    fi
}

simulation_waiver_present() {
    [[ -f "$SIMULATION_WAIVER" ]] && \
        jq -e '.waiver_type == "m42_simulated_go_live" and .approved == true and (.approved_by | type == "string" and length > 0) and (.reason | type == "string" and length > 0)' "$SIMULATION_WAIVER" >/dev/null 2>&1
}

check_runtime_provenance() {
    local name="$1"
    local url="$2"
    local body_path="$REPORT_DIR/${name//[^a-zA-Z0-9_]/_}-health.json"

    mkdir -p "$REPORT_DIR"
    if ! curl -fsS --max-time 10 "$url" -o "$body_path" >/dev/null 2>&1; then
        echo "[FAIL] $name provenance $url" >&2
        return 1
    fi

    if jq -e '.ready == true and .allow_simulated == false and .backend_url == true' "$body_path" >/dev/null 2>&1; then
        echo "[PASS] $name real backend provenance"
        return 0
    fi

    if jq -e '.allow_simulated == true' "$body_path" >/dev/null 2>&1 && simulation_waiver_present; then
        echo "[PASS] $name simulated mode covered by sponsor waiver $SIMULATION_WAIVER"
        return 0
    fi

    echo "[FAIL] $name must report ready=true, allow_simulated=false, backend_url=true unless $SIMULATION_WAIVER is approved" >&2
    return 1
}

post_json() {
    local name="$1"
    local url="$2"
    local payload="$3"
    local jq_filter="${4:-}"
    local body_path="$REPORT_DIR/${name//[^a-zA-Z0-9_]/_}-response.json"
    local status=""

    mkdir -p "$REPORT_DIR"
    if status="$(curl -sS --max-time 20 \
        -H "Content-Type: application/json" \
        -X POST \
        -d "$payload" \
        -o "$body_path" \
        -w "%{http_code}" \
        "$url" 2>/dev/null)"; then
        if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
            if [[ -n "$jq_filter" ]] && ! jq -e "$jq_filter" "$body_path" >/dev/null 2>&1; then
                echo "[FAIL] $name $url HTTP $status response did not match expected evidence shape (response: $body_path)" >&2
                return 1
            fi
            echo "[PASS] $name $url HTTP $status"
            return 0
        fi
        echo "[FAIL] $name $url HTTP $status (response: $body_path)" >&2
        return 1
    fi

    echo "[FAIL] $name $url request failed" >&2
    return 1
}

run_preflight() {
    prepare
    M42_ARCHIVE_DEST="$ARCHIVE_DEST" \
    M42_ALERTMANAGER_ENDPOINT="$ALERTMANAGER_ENDPOINT" \
    M42_PROMETHEUS_ENDPOINT="$PROMETHEUS_ENDPOINT" \
    bash "$ROOT_DIR/scripts/validate-m42-pilot-pretestnet.sh"
}

run_drill() {
    prepare
    python3 "$ROOT_DIR/scripts/m42-sandbox-drill.py" "$@"
}

run_gap_audit() {
    prepare
    python3 "$ROOT_DIR/scripts/m42-pilot-gap-audit.py" "$@"
}

run_live_validation() {
    prepare

    local live_fail=0
    check_http "validator_rpc" "http://$VALIDATOR_RPC/status" || live_fail=1
    check_http "tee_worker" "http://$TEE_ENDPOINT/health" || live_fail=1
    check_http "zkml_prover" "http://$ZKML_PROVER/health" || live_fail=1
    check_runtime_provenance "tee_worker" "http://$TEE_ENDPOINT/health" || live_fail=1
    check_runtime_provenance "zkml_prover" "http://$ZKML_PROVER/health" || live_fail=1
    check_archive || live_fail=1
    check_http "alertmanager" "http://$ALERTMANAGER_ENDPOINT/-/healthy" || live_fail=1
    check_http "prometheus_rules" "http://$PROMETHEUS_ENDPOINT/api/v1/rules" || live_fail=1

    local tee_payload='{"JobID":"m42-live-smoke","ModelHash":"bTQyLW1vZGVsLWhhc2g=","InputHash":"bTQyLWlucHV0LWhhc2g=","InputData":"bTQyLXN5bnRoZXRpYy1pbnB1dA==","Nonce":"bTQyLW5vbmNlLWZyZXNobmVzcw==","RequireZKProof":true,"Metadata":{"pilot":"m42","workload":"m42-med42-synthetic-eval","data_status":"synthetic_non_live"},"BlockHeight":1,"ChainID":"aethelred-m42-pilot-1"}'
    local zkml_payload='{"model_hash":"bTQyLW1vZGVsLWhhc2g=","circuit_hash":"bTQyLWNpcmN1aXQtaGFzaA==","input_data":"bTQyLXN5bnRoZXRpYy1pbnB1dA==","input_hash":"bTQyLWlucHV0LWhhc2g=","output_data":"bTQyLXN5bnRoZXRpYy1vdXRwdXQ=","output_hash":"bTQyLW91dHB1dC1oYXNo","verifying_key_hash":"bTQyLXZlcmlmeWluZy1rZXktaGFzaA==","request_id":"m42-live-smoke","priority":1}'
    post_json "tee_execute_smoke" "http://$TEE_ENDPOINT/execute" "$tee_payload" '.Success == true and (.Attestation != null) and (.ZKProof != null)' || live_fail=1
    post_json "zkml_prove_smoke" "http://$ZKML_PROVER/prove" "$zkml_payload" '.success == true and (.proof != null) and (.public_inputs != null)' || live_fail=1

    AETHELRED_ARCHIVE_USER="$ARCHIVE_USER" \
    AETHELRED_ARCHIVE_PASSWORD="${M42_ARCHIVE_ADMIN_PASSWORD:-}" \
    bash "$ROOT_DIR/scripts/validate-pilot-deployment.sh" \
        --pilot-name m42-med42-synthetic-eval \
        --workload-pack "$WORKLOAD_PACK" \
        --model-hash "$MODEL_HASH" \
        --circuit-hash "$CIRCUIT_HASH" \
        --registry-dir "$REGISTRY_DIR" \
        --evidence-path "$EVIDENCE_PATH" \
        --archive-dest "$ARCHIVE_DEST" \
        --archive-scheme "$ARCHIVE_SCHEME" \
        --alertmanager "$ALERTMANAGER_ENDPOINT" \
        --prometheus "$PROMETHEUS_ENDPOINT" \
        --validator-rpc "$VALIDATOR_RPC" \
        --validator-grpc "$VALIDATOR_GRPC" \
        --tee-endpoint "$TEE_ENDPOINT" \
        --attestation "$ATTESTATION_ENDPOINT" \
        --prover-ezkl "$ZKML_PROVER" \
        --prover-risczero "$ZKML_PROVER" \
        --prover-groth16 "$ZKML_PROVER" \
        --bridge "$BRIDGE_ENDPOINT" \
        --grafana "$GRAFANA_ENDPOINT" \
        --topology PILOT \
        --output "$REPORT_DIR/m42-sandbox-live-validation.json" || live_fail=1

    if [[ "$live_fail" -ne 0 ]]; then
        echo "M42 sandbox live validation failed. Start the sandbox with: scripts/m42-sandbox.sh up" >&2
        exit 1
    fi
}

cmd="${1:-help}"
shift || true

case "$cmd" in
    prepare)
        prepare
        ;;
    up)
        prepare
        compose up -d "$@"
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
    config)
        prepare
        compose config "$@"
        ;;
    pin-images)
        pin_images
        ;;
    preflight)
        run_preflight
        ;;
    drill)
        run_drill
        ;;
    drill-all)
        run_drill --all
        ;;
    gap-audit)
        run_gap_audit
        ;;
    gap-audit-strict)
        run_gap_audit --strict
        ;;
    validate)
        run_live_validation
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        echo "Unknown command: $cmd" >&2
        usage >&2
        exit 2
        ;;
esac
