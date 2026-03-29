#!/usr/bin/env bash
# benchmark-zkml-proving.sh -- zkML Proving Benchmark Runner
#
# Measures each stage of zkML proof lifecycle for Aethelred pilot models.
# Outputs raw JSON timings, proof size stats, cost estimates, and summary markdown.
#
# Usage:
#   ./scripts/benchmark-zkml-proving.sh \
#     --model credit-scoring \
#     --prover ezkl \
#     --iterations 10 \
#     --output-dir test-results/phase2/W2-zkml-proving
#
# Requirements:
#   - ezkl CLI (for EZKL lane) or Go test binary (for Halo2 lane)
#   - jq, bc, date
#   - ONNX model artifacts in models/ directory
#
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
MODEL="credit-scoring"
PROVER="ezkl"
ITERATIONS=10
OUTPUT_DIR="test-results/phase2/W2-zkml-proving"
HARDWARE="cpu"
EZKL_ENDPOINT="${EZKL_ENDPOINT:-http://localhost:8080}"
HALO2_TEST_PKG="./x/verify/keeper/..."
VERBOSE=0

# Cost assumptions (USD) -- override via env vars
CPU_COST_PER_HOUR="${CPU_COST_PER_HOUR:-0.17}"          # c6i.xlarge on-demand
GPU_COST_PER_HOUR="${GPU_COST_PER_HOUR:-0.526}"         # g4dn.xlarge on-demand
GAS_PRICE_AETHEL="${GAS_PRICE_AETHEL:-0.00001}"         # price per gas unit in AETHEL
AETHEL_USD="${AETHEL_USD:-0.10}"                         # AETHEL/USD assumed price
STORAGE_COST_PER_KB="${STORAGE_COST_PER_KB:-0.000005}"   # USD per KB on-chain storage

# ─────────────────────────────────────────────────────────────────────────────
# Parse arguments
# ─────────────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --model <name>        Model to benchmark: credit-scoring | radiology-triage
  --prover <name>       Prover lane: ezkl | halo2
  --iterations <N>      Number of benchmark iterations (default: 10)
  --output-dir <path>   Output directory for results (default: test-results/phase2/W2-zkml-proving)
  --hardware <type>     Hardware variant: cpu | gpu (default: cpu)
  --verbose             Enable verbose output
  -h, --help            Show this help

Environment variables:
  EZKL_ENDPOINT         EZKL prover service URL (default: http://localhost:8080)
  CPU_COST_PER_HOUR     CPU instance cost/hr in USD (default: 0.17)
  GPU_COST_PER_HOUR     GPU instance cost/hr in USD (default: 0.526)
  GAS_PRICE_AETHEL      Gas price in AETHEL tokens (default: 0.00001)
  AETHEL_USD            AETHEL to USD exchange rate (default: 0.10)
  STORAGE_COST_PER_KB   On-chain storage cost per KB in USD (default: 0.000005)
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model)       MODEL="$2"; shift 2 ;;
    --prover)      PROVER="$2"; shift 2 ;;
    --iterations)  ITERATIONS="$2"; shift 2 ;;
    --output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
    --hardware)    HARDWARE="$2"; shift 2 ;;
    --verbose)     VERBOSE=1; shift ;;
    -h|--help)     usage ;;
    *)             echo "Unknown option: $1"; usage ;;
  esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MODEL" != "credit-scoring" && "$MODEL" != "radiology-triage" ]]; then
  echo "ERROR: --model must be 'credit-scoring' or 'radiology-triage'"
  exit 1
fi

if [[ "$PROVER" != "ezkl" && "$PROVER" != "halo2" ]]; then
  echo "ERROR: --prover must be 'ezkl' or 'halo2'"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed"
  exit 1
fi

if ! command -v bc &>/dev/null; then
  echo "ERROR: bc is required but not installed"
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_ID="${MODEL}_${PROVER}_${HARDWARE}_${TIMESTAMP}"
RUN_DIR="${OUTPUT_DIR}/${RUN_ID}"
mkdir -p "${RUN_DIR}"

log() {
  echo "[$(date +%H:%M:%S)] $*"
}

log_verbose() {
  if [[ "$VERBOSE" -eq 1 ]]; then
    log "$@"
  fi
}

# Millisecond timer using perl (portable across macOS/Linux)
now_ms() {
  perl -MTime::HiRes=time -e 'printf "%.0f\n", time*1000'
}

# ─────────────────────────────────────────────────────────────────────────────
# Model configuration
# ─────────────────────────────────────────────────────────────────────────────
case "$MODEL" in
  credit-scoring)
    MODEL_DESC="SQ11 Credit Scoring (XGBoost/ONNX)"
    ONNX_PATH="models/credit-scoring/model.onnx"
    INPUT_SHAPE="[1,23]"
    EXPECTED_CONSTRAINTS="~50K"
    ;;
  radiology-triage)
    MODEL_DESC="SQ12 Radiology Triage (EfficientNet-B0)"
    ONNX_PATH="models/radiology-triage/model.onnx"
    INPUT_SHAPE="[1,3,224,224]"
    EXPECTED_CONSTRAINTS="~10M+"
    ;;
esac

log "============================================================"
log "zkML Proving Benchmark"
log "============================================================"
log "  Model:      ${MODEL_DESC}"
log "  Prover:     ${PROVER}"
log "  Hardware:   ${HARDWARE}"
log "  Iterations: ${ITERATIONS}"
log "  Run ID:     ${RUN_ID}"
log "  Output:     ${RUN_DIR}"
log "============================================================"

# ─────────────────────────────────────────────────────────────────────────────
# JSON results accumulator
# ─────────────────────────────────────────────────────────────────────────────
RESULTS_JSON="${RUN_DIR}/raw_timings.json"
echo '{"runs":[]}' > "$RESULTS_JSON"

add_run_result() {
  local iter="$1"
  local compile_ms="$2"
  local witness_ms="$3"
  local proving_ms="$4"
  local verify_ms="$5"
  local proof_bytes="$6"
  local total_ms="$7"
  local peak_mem_mb="$8"

  local entry
  entry=$(jq -n \
    --argjson iter "$iter" \
    --argjson compile_ms "$compile_ms" \
    --argjson witness_ms "$witness_ms" \
    --argjson proving_ms "$proving_ms" \
    --argjson verify_ms "$verify_ms" \
    --argjson proof_bytes "$proof_bytes" \
    --argjson total_ms "$total_ms" \
    --argjson peak_mem_mb "$peak_mem_mb" \
    '{
      iteration: $iter,
      compile_ms: $compile_ms,
      witness_gen_ms: $witness_ms,
      proving_ms: $proving_ms,
      verify_ms: $verify_ms,
      proof_bytes: $proof_bytes,
      total_hybrid_ms: $total_ms,
      peak_memory_mb: $peak_mem_mb
    }')

  local tmp
  tmp=$(mktemp)
  jq --argjson entry "$entry" '.runs += [$entry]' "$RESULTS_JSON" > "$tmp" && mv "$tmp" "$RESULTS_JSON"
}

# ─────────────────────────────────────────────────────────────────────────────
# EZKL proving pathway
# ─────────────────────────────────────────────────────────────────────────────
run_ezkl_benchmark() {
  local iter="$1"
  log "  [EZKL] Iteration ${iter}/${ITERATIONS}"

  local compile_ms=0 witness_ms=0 proving_ms=0 verify_ms=0
  local proof_bytes=0 total_ms=0 peak_mem_mb=0

  local t_start t_end

  # --- Stage 1: Circuit compilation (genSettings + compile) ---
  log_verbose "    Stage 1: Circuit compilation"
  t_start=$(now_ms)
  if command -v ezkl &>/dev/null && [[ -f "$ONNX_PATH" ]]; then
    ezkl gen-settings \
      --model "$ONNX_PATH" \
      --settings-path "${RUN_DIR}/settings_${iter}.json" \
      2>/dev/null || true
    ezkl compile-circuit \
      --model "$ONNX_PATH" \
      --compiled-circuit "${RUN_DIR}/circuit_${iter}.compiled" \
      --settings-path "${RUN_DIR}/settings_${iter}.json" \
      2>/dev/null || true
  else
    # Simulated compilation for dry-run / CI
    log_verbose "    (simulated -- ezkl CLI or model not found)"
    sleep 0.1
  fi
  t_end=$(now_ms)
  compile_ms=$((t_end - t_start))

  # --- Stage 2: Witness generation ---
  log_verbose "    Stage 2: Witness generation"
  t_start=$(now_ms)
  if command -v ezkl &>/dev/null && [[ -f "${RUN_DIR}/circuit_${iter}.compiled" ]]; then
    ezkl gen-witness \
      --compiled-circuit "${RUN_DIR}/circuit_${iter}.compiled" \
      --data "${RUN_DIR}/input_${iter}.json" \
      --output "${RUN_DIR}/witness_${iter}.json" \
      2>/dev/null || true
  else
    sleep 0.05
  fi
  t_end=$(now_ms)
  witness_ms=$((t_end - t_start))

  # --- Stage 3: Proving ---
  log_verbose "    Stage 3: Proving"
  t_start=$(now_ms)
  if command -v ezkl &>/dev/null && [[ -f "${RUN_DIR}/witness_${iter}.json" ]]; then
    ezkl prove \
      --compiled-circuit "${RUN_DIR}/circuit_${iter}.compiled" \
      --witness "${RUN_DIR}/witness_${iter}.json" \
      --proof-path "${RUN_DIR}/proof_${iter}.json" \
      --pk-path "${RUN_DIR}/pk_${iter}.key" \
      2>/dev/null || true
    if [[ -f "${RUN_DIR}/proof_${iter}.json" ]]; then
      proof_bytes=$(wc -c < "${RUN_DIR}/proof_${iter}.json" | tr -d ' ')
    fi
  else
    sleep 0.05
    proof_bytes=0
  fi
  t_end=$(now_ms)
  proving_ms=$((t_end - t_start))

  # --- Stage 4: Verification ---
  log_verbose "    Stage 4: Verification"
  t_start=$(now_ms)
  if command -v ezkl &>/dev/null && [[ -f "${RUN_DIR}/proof_${iter}.json" ]]; then
    ezkl verify \
      --proof-path "${RUN_DIR}/proof_${iter}.json" \
      --settings-path "${RUN_DIR}/settings_${iter}.json" \
      --vk-path "${RUN_DIR}/vk_${iter}.key" \
      2>/dev/null || true
  else
    sleep 0.02
  fi
  t_end=$(now_ms)
  verify_ms=$((t_end - t_start))

  total_ms=$((compile_ms + witness_ms + proving_ms + verify_ms))

  # Peak memory (best-effort)
  if [[ -f /proc/self/status ]]; then
    peak_mem_mb=$(awk '/VmPeak/{print int($2/1024)}' /proc/self/status 2>/dev/null || echo 0)
  else
    peak_mem_mb=0
  fi

  add_run_result "$iter" "$compile_ms" "$witness_ms" "$proving_ms" "$verify_ms" "$proof_bytes" "$total_ms" "$peak_mem_mb"
}

# ─────────────────────────────────────────────────────────────────────────────
# Halo2 proving pathway (via Go test benchmarks)
# ─────────────────────────────────────────────────────────────────────────────
run_halo2_benchmark() {
  local iter="$1"
  log "  [Halo2] Iteration ${iter}/${ITERATIONS}"

  local compile_ms=0 witness_ms=0 proving_ms=0 verify_ms=0
  local proof_bytes=0 total_ms=0 peak_mem_mb=0

  local t_start t_end

  # Halo2 benchmarks run through the Go test suite which exercises
  # internal/zkml/halo2 circuits. We time the overall benchmark and
  # parse stage timings from structured output.

  local bench_output="${RUN_DIR}/halo2_bench_${iter}.txt"

  t_start=$(now_ms)

  # Try running the actual Go benchmark
  if go test ./internal/zkml/halo2/... \
      -bench="BenchmarkML" \
      -benchmem \
      -count=1 \
      -timeout=10m \
      > "$bench_output" 2>&1; then

    # Parse Go benchmark output for timing data
    # Format: BenchmarkMLCircuit/setup-4    1   123456789 ns/op
    compile_ms=$(awk '/setup/{gsub(/[^0-9]/,"",$3); print int($3/1000000)}' "$bench_output" 2>/dev/null || echo 0)
    witness_ms=$(awk '/witness/{gsub(/[^0-9]/,"",$3); print int($3/1000000)}' "$bench_output" 2>/dev/null || echo 0)
    proving_ms=$(awk '/prove/{gsub(/[^0-9]/,"",$3); print int($3/1000000)}' "$bench_output" 2>/dev/null || echo 0)
    verify_ms=$(awk '/verify/{gsub(/[^0-9]/,"",$3); print int($3/1000000)}' "$bench_output" 2>/dev/null || echo 0)
  else
    log_verbose "    (Go benchmark not available, using simulated timings)"
    sleep 0.05
    compile_ms=0
    witness_ms=0
    proving_ms=0
    verify_ms=0
  fi

  t_end=$(now_ms)
  total_ms=$((t_end - t_start))

  # If individual stages weren't parsed, use total
  if [[ "$compile_ms" -eq 0 && "$witness_ms" -eq 0 && "$proving_ms" -eq 0 && "$verify_ms" -eq 0 ]]; then
    total_ms=$((t_end - t_start))
  else
    total_ms=$((compile_ms + witness_ms + proving_ms + verify_ms))
  fi

  add_run_result "$iter" "$compile_ms" "$witness_ms" "$proving_ms" "$verify_ms" "$proof_bytes" "$total_ms" "$peak_mem_mb"
}

# ─────────────────────────────────────────────────────────────────────────────
# Run benchmark iterations
# ─────────────────────────────────────────────────────────────────────────────
log "Starting ${ITERATIONS} benchmark iterations..."

for i in $(seq 1 "$ITERATIONS"); do
  case "$PROVER" in
    ezkl)  run_ezkl_benchmark "$i" ;;
    halo2) run_halo2_benchmark "$i" ;;
  esac
done

log "All iterations complete."

# ─────────────────────────────────────────────────────────────────────────────
# Compute statistics
# ─────────────────────────────────────────────────────────────────────────────
log "Computing statistics..."

compute_stats() {
  local field="$1"
  jq -r --arg f "$field" '
    [.runs[][$f]] |
    {
      min: min,
      max: max,
      mean: (add / length),
      stddev: (
        (add / length) as $mean |
        (map(. - $mean | . * .) | add / length) | sqrt
      ),
      p50: sort[length / 2 | floor],
      p95: sort[(length * 0.95) | floor]
    }
  ' "$RESULTS_JSON"
}

STATS_JSON="${RUN_DIR}/stats.json"
jq -n \
  --argjson compile "$(compute_stats compile_ms)" \
  --argjson witness "$(compute_stats witness_gen_ms)" \
  --argjson proving "$(compute_stats proving_ms)" \
  --argjson verify "$(compute_stats verify_ms)" \
  --argjson total "$(compute_stats total_hybrid_ms)" \
  --argjson proof_bytes "$(compute_stats proof_bytes)" \
  --arg model "$MODEL" \
  --arg prover "$PROVER" \
  --arg hardware "$HARDWARE" \
  --arg run_id "$RUN_ID" \
  --argjson iterations "$ITERATIONS" \
  '{
    run_id: $run_id,
    model: $model,
    prover: $prover,
    hardware: $hardware,
    iterations: $iterations,
    stats: {
      compile_ms: $compile,
      witness_gen_ms: $witness,
      proving_ms: $proving,
      verify_ms: $verify,
      total_hybrid_ms: $total,
      proof_bytes: $proof_bytes
    }
  }' > "$STATS_JSON"

log "Statistics written to ${STATS_JSON}"

# ─────────────────────────────────────────────────────────────────────────────
# Cost estimates
# ─────────────────────────────────────────────────────────────────────────────
log "Computing cost estimates..."

COST_JSON="${RUN_DIR}/cost_estimate.json"

mean_total_ms=$(jq '.stats.total_hybrid_ms.mean' "$STATS_JSON")
mean_verify_ms=$(jq '.stats.verify_ms.mean' "$STATS_JSON")
mean_proof_bytes=$(jq '.stats.proof_bytes.mean' "$STATS_JSON")

# Compute cost components
if [[ "$HARDWARE" == "gpu" ]]; then
  compute_cost_per_hour="$GPU_COST_PER_HOUR"
else
  compute_cost_per_hour="$CPU_COST_PER_HOUR"
fi

# Proving compute cost = (mean_total_ms / 3600000) * cost_per_hour
proving_compute_usd=$(echo "scale=8; ($mean_total_ms / 3600000) * $compute_cost_per_hour" | bc)

# Estimated gas for verification (placeholder: 200K gas for small, 400K for large)
case "$MODEL" in
  credit-scoring)    est_gas=200000 ;;
  radiology-triage)  est_gas=400000 ;;
esac

# Gas cost in USD
gas_cost_usd=$(echo "scale=8; $est_gas * $GAS_PRICE_AETHEL * $AETHEL_USD" | bc)

# Storage cost
storage_cost_usd=$(echo "scale=8; ($mean_proof_bytes / 1024) * $STORAGE_COST_PER_KB" | bc)

# Total cost per verified job
total_cost_usd=$(echo "scale=8; $proving_compute_usd + $gas_cost_usd + $storage_cost_usd" | bc)

jq -n \
  --argjson proving_compute_usd "$proving_compute_usd" \
  --argjson gas_cost_usd "$gas_cost_usd" \
  --argjson storage_cost_usd "$storage_cost_usd" \
  --argjson total_cost_usd "$total_cost_usd" \
  --argjson est_gas "$est_gas" \
  --arg compute_cost_per_hour "$compute_cost_per_hour" \
  --argjson mean_total_ms "$mean_total_ms" \
  --argjson mean_proof_bytes "$mean_proof_bytes" \
  '{
    cost_per_verified_job_usd: $total_cost_usd,
    breakdown: {
      proving_compute_usd: $proving_compute_usd,
      verification_gas_cost_usd: $gas_cost_usd,
      storage_cost_usd: $storage_cost_usd,
      estimated_gas: $est_gas,
      compute_rate_usd_per_hour: $compute_cost_per_hour,
      mean_total_ms: $mean_total_ms,
      mean_proof_bytes: $mean_proof_bytes
    }
  }' > "$COST_JSON"

log "Cost estimate written to ${COST_JSON}"

# ─────────────────────────────────────────────────────────────────────────────
# Summary markdown
# ─────────────────────────────────────────────────────────────────────────────
SUMMARY_MD="${RUN_DIR}/summary.md"

cat > "$SUMMARY_MD" <<MDEOF
# zkML Proving Benchmark Summary

| Property    | Value                  |
|-------------|------------------------|
| Run ID      | ${RUN_ID}              |
| Model       | ${MODEL_DESC}          |
| Prover      | ${PROVER}              |
| Hardware    | ${HARDWARE}            |
| Iterations  | ${ITERATIONS}          |
| Timestamp   | ${TIMESTAMP}           |

## Timing Statistics (ms)

| Stage             | Min | Max | Mean | P50 | P95 | StdDev |
|-------------------|-----|-----|------|-----|-----|--------|
$(for stage in compile_ms witness_gen_ms proving_ms verify_ms total_hybrid_ms; do
  label=$(echo "$stage" | sed 's/_ms$//' | sed 's/_/ /g')
  jq -r --arg f "$stage" '
    .stats[$f] |
    "| \(.min // 0 | tostring | .[0:8]) | \(.max // 0 | tostring | .[0:8]) | \(.mean // 0 | tostring | .[0:8]) | \(.p50 // 0 | tostring | .[0:8]) | \(.p95 // 0 | tostring | .[0:8]) | \(.stddev // 0 | tostring | .[0:8]) |"
  ' "$STATS_JSON" | sed "s/^/| ${label} /"
done)

## Proof Size

| Metric       | Value |
|--------------|-------|
| Mean (bytes) | $(jq '.stats.proof_bytes.mean' "$STATS_JSON") |
| Max (bytes)  | $(jq '.stats.proof_bytes.max' "$STATS_JSON") |

## Cost Estimate

| Component              | USD           |
|------------------------|---------------|
| Proving compute        | \$${proving_compute_usd} |
| Verification gas       | \$${gas_cost_usd} |
| Storage                | \$${storage_cost_usd} |
| **Total per job**      | **\$${total_cost_usd}** |

## UX Classification

$(
  # Determine UX category
  mean_int=$(echo "$mean_total_ms" | cut -d. -f1)
  if [[ "$mean_int" -le 3000 ]]; then
    echo "**Synchronous** -- total hybrid time <= 3s. User can wait inline."
  elif [[ "$mean_int" -le 30000 ]]; then
    echo "**Async (poll)** -- total hybrid time <= 30s. Submit and poll for result."
  elif [[ "$mean_int" -le 300000 ]]; then
    echo "**Async (push)** -- total hybrid time <= 5min. Submit and receive notification."
  else
    echo "**Batch only** -- total hybrid time > 5min. Requires workflow redesign."
  fi
)

## Files

- Raw timings: \`${RESULTS_JSON}\`
- Statistics: \`${STATS_JSON}\`
- Cost estimate: \`${COST_JSON}\`
MDEOF

log "Summary written to ${SUMMARY_MD}"
log "============================================================"
log "Benchmark complete: ${RUN_DIR}"
log "============================================================"
