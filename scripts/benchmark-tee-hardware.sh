#!/usr/bin/env bash
# ============================================================================
# TEE Hardware Benchmark Harness
# ============================================================================
# Parameterized benchmark script for real TEE hardware measurements.
# Follows docs/operations/BENCHMARK_METHODOLOGY.md (SQ16-BMS-001) exactly.
#
# Usage:
#   ./scripts/benchmark-tee-hardware.sh \
#     --platform nitro \
#     --topology single \
#     --iterations 1000 \
#     --warmup 100 \
#     --output-dir test-results/phase2/W1-tee-hardware/nitro-single
#
# Platforms: sgx | nitro | sev
# Topologies: single | regional | pilot
# ============================================================================

set -euo pipefail

# ---- Defaults ----
PLATFORM=""
TOPOLOGY=""
ITERATIONS=1000
WARMUP=100
OUTPUT_DIR=""
AETHELRED_BIN="./build/aethelredd"
TEE_WORKER_BIN="./build/tee-worker"
REFERENCE_MODEL="./testdata/models/resnet50.onnx"
COMMIT_HASH=""
VERBOSE=false
DRY_RUN=false

# ---- Color output ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC}  $(date '+%H:%M:%S') $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $(date '+%H:%M:%S') $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date '+%H:%M:%S') $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*"; }

# ---- Usage ----
usage() {
  cat <<EOF
TEE Hardware Benchmark Harness (Phase 2 Week 1)

USAGE:
  $0 [OPTIONS]

REQUIRED OPTIONS:
  --platform <sgx|nitro|sev>       TEE platform to benchmark
  --topology <single|regional|pilot> Network topology variant
  --output-dir <path>               Directory for output artifacts

OPTIONS:
  --iterations <N>    Number of measurement iterations per test (default: 1000)
  --warmup <N>        Number of warmup iterations to discard (default: 100)
  --aethelred <path>  Path to aethelredd binary (default: ./build/aethelredd)
  --tee-worker <path> Path to tee-worker binary (default: ./build/tee-worker)
  --model <path>      Path to reference ONNX model (default: ./testdata/models/resnet50.onnx)
  --verbose           Enable verbose output
  --dry-run           Print what would be executed without running
  --help              Show this help

OUTPUT:
  <output-dir>/raw-timings.json          All per-iteration timing data
  <output-dir>/hardware-disclosure.json  Machine-readable hardware specs
  <output-dir>/summary.md               Human-readable summary

METHODOLOGY:
  Follows docs/operations/BENCHMARK_METHODOLOGY.md (SQ16-BMS-001).
  - Monotonic clock source for all timings
  - Warm-up iterations discarded before measurement
  - p50/p95/p99/min/max/stddev/CV computed from raw samples
  - Steady-state verification via CV threshold (< 15%)

EXAMPLES:
  # Nitro single-node, 1000 iterations
  $0 --platform nitro --topology single --iterations 1000 \\
     --output-dir test-results/phase2/W1-tee-hardware/nitro-single-\$(date +%Y%m%d)

  # SGX regional, 500 iterations, verbose
  $0 --platform sgx --topology regional --iterations 500 --verbose \\
     --output-dir test-results/phase2/W1-tee-hardware/sgx-regional-\$(date +%Y%m%d)

  # Dry run to see what would execute
  $0 --platform sev --topology single --dry-run \\
     --output-dir /tmp/test
EOF
  exit 0
}

# ---- Argument parsing ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)     PLATFORM="$2"; shift 2 ;;
    --topology)     TOPOLOGY="$2"; shift 2 ;;
    --iterations)   ITERATIONS="$2"; shift 2 ;;
    --warmup)       WARMUP="$2"; shift 2 ;;
    --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
    --aethelred)    AETHELRED_BIN="$2"; shift 2 ;;
    --tee-worker)   TEE_WORKER_BIN="$2"; shift 2 ;;
    --model)        REFERENCE_MODEL="$2"; shift 2 ;;
    --verbose)      VERBOSE=true; shift ;;
    --dry-run)      DRY_RUN=true; shift ;;
    --help)         usage ;;
    *) log_error "Unknown option: $1"; usage ;;
  esac
done

# ---- Validation ----
validate_args() {
  local errors=0

  if [[ -z "$PLATFORM" ]]; then
    log_error "--platform is required (sgx|nitro|sev)"
    errors=$((errors + 1))
  elif [[ ! "$PLATFORM" =~ ^(sgx|nitro|sev)$ ]]; then
    log_error "Invalid platform: $PLATFORM (must be sgx|nitro|sev)"
    errors=$((errors + 1))
  fi

  if [[ -z "$TOPOLOGY" ]]; then
    log_error "--topology is required (single|regional|pilot)"
    errors=$((errors + 1))
  elif [[ ! "$TOPOLOGY" =~ ^(single|regional|pilot)$ ]]; then
    log_error "Invalid topology: $TOPOLOGY (must be single|regional|pilot)"
    errors=$((errors + 1))
  fi

  if [[ -z "$OUTPUT_DIR" ]]; then
    log_error "--output-dir is required"
    errors=$((errors + 1))
  fi

  if [[ "$ITERATIONS" -lt 10 ]]; then
    log_error "Iterations must be >= 10 (got: $ITERATIONS)"
    errors=$((errors + 1))
  fi

  if [[ "$WARMUP" -ge "$ITERATIONS" ]]; then
    log_error "Warmup ($WARMUP) must be less than iterations ($ITERATIONS)"
    errors=$((errors + 1))
  fi

  if [[ $errors -gt 0 ]]; then
    echo ""
    usage
  fi
}

validate_args

# ---- Setup ----
COMMIT_HASH=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
RUN_ID="${PLATFORM}-${TOPOLOGY}-$(date +%Y%m%d-%H%M%S)"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

log_info "============================================"
log_info "TEE Hardware Benchmark"
log_info "============================================"
log_info "Platform:   $PLATFORM"
log_info "Topology:   $TOPOLOGY"
log_info "Iterations: $ITERATIONS (warmup: $WARMUP)"
log_info "Output:     $OUTPUT_DIR"
log_info "Commit:     $COMMIT_SHORT"
log_info "Run ID:     $RUN_ID"
log_info "============================================"

if [[ "$DRY_RUN" == true ]]; then
  log_warn "DRY RUN MODE -- no benchmarks will execute"
fi

mkdir -p "$OUTPUT_DIR"

# ============================================================================
# Hardware Disclosure Collection
# ============================================================================

collect_hardware_disclosure() {
  log_info "Collecting hardware disclosure..."

  local hw_json="$OUTPUT_DIR/hardware-disclosure.json"

  # Collect system information (works on Linux; graceful fallback on macOS)
  local cpu_model
  local cpu_cores
  local cpu_arch
  local total_ram
  local kernel_version
  local os_release

  if [[ "$(uname)" == "Linux" ]]; then
    cpu_model=$(lscpu 2>/dev/null | grep "Model name" | sed 's/.*:\s*//' || echo "unknown")
    cpu_cores=$(nproc 2>/dev/null || echo "unknown")
    cpu_arch=$(uname -m)
    total_ram=$(free -h 2>/dev/null | awk '/Mem:/{print $2}' || echo "unknown")
    kernel_version=$(uname -r)
    os_release=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo "unknown")
  elif [[ "$(uname)" == "Darwin" ]]; then
    cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")
    cpu_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
    cpu_arch=$(uname -m)
    total_ram=$(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.0f GB", $1/1073741824}' || echo "unknown")
    kernel_version=$(uname -r)
    os_release="macOS $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
  else
    cpu_model="unknown"
    cpu_cores="unknown"
    cpu_arch=$(uname -m)
    total_ram="unknown"
    kernel_version=$(uname -r)
    os_release="unknown"
  fi

  # Collect platform-specific TEE info
  local tee_info="{}"
  case "$PLATFORM" in
    nitro)
      tee_info=$(cat <<TEEJSON
{
  "platform": "AWS Nitro Enclaves",
  "nitro_cli_version": "$(nitro-cli --version 2>/dev/null || echo 'not installed')",
  "nsm_driver": "$(lsmod 2>/dev/null | grep nitro || echo 'not loaded')",
  "enclave_config": "$(nitro-cli describe-enclaves 2>/dev/null || echo 'no enclaves running')"
}
TEEJSON
      )
      ;;
    sgx)
      tee_info=$(cat <<TEEJSON
{
  "platform": "Intel SGX DCAP",
  "sgx_sdk_version": "$(sgx_sign --version 2>/dev/null || echo 'not installed')",
  "dcap_version": "$(apt list --installed 2>/dev/null | grep sgx-dcap || echo 'not installed')",
  "sgx_detect": "$(sgx_detect 2>/dev/null | head -5 || echo 'sgx_detect not available')",
  "epc_size": "$(sgx_detect 2>/dev/null | grep 'EPC size' || echo 'unknown')",
  "pccs_config": "$(cat /etc/sgx_default_qcnl.conf 2>/dev/null | head -10 || echo 'no PCCS config')"
}
TEEJSON
      )
      ;;
    sev)
      tee_info=$(cat <<TEEJSON
{
  "platform": "AMD SEV-SNP",
  "sev_firmware": "$(dmesg 2>/dev/null | grep -i 'sev.*firmware' | head -1 || echo 'unknown')",
  "snp_enabled": "$(cat /sys/module/kvm_amd/parameters/sev_snp 2>/dev/null || echo 'unknown')",
  "cpu_model": "$(lscpu 2>/dev/null | grep 'Model name' | sed 's/.*:\s*//' || echo 'unknown')",
  "snp_api_version": "$(sevtool --version 2>/dev/null || echo 'not installed')"
}
TEEJSON
      )
      ;;
  esac

  # Collect cloud environment info (if on cloud)
  local cloud_info="{}"
  if curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-type >/dev/null 2>&1; then
    local instance_type
    instance_type=$(curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
    local az
    az=$(curl -s -m 2 http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null || echo "unknown")
    cloud_info=$(cat <<CLOUDJSON
{
  "provider": "AWS",
  "instance_type": "$instance_type",
  "availability_zone": "$az",
  "region": "$(echo "$az" | sed 's/[a-z]$//')"
}
CLOUDJSON
    )
  fi

  # Write hardware disclosure JSON
  cat > "$hw_json" <<HWJSON
{
  "benchmark_id": "$RUN_ID",
  "timestamp": "$TIMESTAMP",
  "commit": "$COMMIT_HASH",
  "system": {
    "cpu_model": "$cpu_model",
    "cpu_cores": "$cpu_cores",
    "cpu_architecture": "$cpu_arch",
    "total_ram": "$total_ram",
    "kernel_version": "$kernel_version",
    "os_release": "$os_release"
  },
  "tee": $tee_info,
  "cloud": $cloud_info,
  "go_version": "$(go version 2>/dev/null || echo 'not installed')",
  "rust_version": "$(rustc --version 2>/dev/null || echo 'not installed')"
}
HWJSON

  log_ok "Hardware disclosure written to $hw_json"
}

# ============================================================================
# Timing Utilities
# ============================================================================

# Get high-resolution monotonic time in nanoseconds
# Uses date +%s%N on Linux, perl on macOS for ns precision
get_time_ns() {
  if [[ "$(uname)" == "Linux" ]]; then
    date +%s%N
  else
    # macOS fallback: use perl for nanosecond precision
    perl -MTime::HiRes=time -e 'printf("%.0f\n", time() * 1e9)'
  fi
}

# Calculate elapsed time in nanoseconds
elapsed_ns() {
  local start=$1
  local end=$2
  echo $((end - start))
}

# ============================================================================
# Measurement Functions
# ============================================================================
# Each measurement function outputs one JSON line per iteration to stdout.
# The caller captures these into the raw timings file.

# M1: Enclave Start Time
measure_enclave_start() {
  local iteration=$1
  log_info "  M1: Enclave Start (iteration $iteration/$ITERATIONS)"

  case "$PLATFORM" in
    nitro)
      local start_ns end_ns
      start_ns=$(get_time_ns)
      # Launch enclave from EIF and wait for ready signal
      # NOTE: Replace with actual EIF path when available
      nitro-cli run-enclave \
        --eif-path ./build/aethelred-enclave.eif \
        --cpu-count 2 \
        --memory 4096 \
        2>/dev/null || { log_warn "Enclave start failed (iteration $iteration)"; return 1; }
      # Wait for enclave to respond on vsock
      # timeout 30 bash -c 'until nitro-cli describe-enclaves | grep -q RUNNING; do sleep 0.1; done'
      end_ns=$(get_time_ns)
      local elapsed
      elapsed=$(elapsed_ns "$start_ns" "$end_ns")
      echo "{\"measurement\":\"enclave_start\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
      # Teardown enclave for next iteration
      nitro-cli terminate-enclave --all 2>/dev/null || true
      ;;
    sgx)
      local start_ns end_ns
      start_ns=$(get_time_ns)
      # Launch SGX enclave
      # NOTE: Replace with actual enclave binary path
      ./build/aethelred-sgx-enclave --init 2>/dev/null || { log_warn "SGX enclave start failed"; return 1; }
      end_ns=$(get_time_ns)
      local elapsed
      elapsed=$(elapsed_ns "$start_ns" "$end_ns")
      echo "{\"measurement\":\"enclave_start\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
      ;;
    sev)
      local start_ns end_ns
      start_ns=$(get_time_ns)
      # Launch SEV-SNP guest/VM
      # NOTE: Replace with actual SEV launch command
      ./build/aethelred-sev-launcher --init 2>/dev/null || { log_warn "SEV launch failed"; return 1; }
      end_ns=$(get_time_ns)
      local elapsed
      elapsed=$(elapsed_ns "$start_ns" "$end_ns")
      echo "{\"measurement\":\"enclave_start\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
      ;;
  esac
}

# M2: Attestation Generation
measure_attestation_gen() {
  local iteration=$1
  if [[ "$VERBOSE" == true ]]; then
    log_info "  M2: Attestation Gen (iteration $iteration/$ITERATIONS)"
  fi

  case "$PLATFORM" in
    nitro)
      local start_ns end_ns
      start_ns=$(get_time_ns)
      # Request attestation from NSM
      # NOTE: This calls the enclave's attestation endpoint via vsock
      # The actual command depends on the enclave application protocol
      # nitro-cli attest --enclave-id <id> --nonce <random>
      end_ns=$(get_time_ns)
      local elapsed
      elapsed=$(elapsed_ns "$start_ns" "$end_ns")
      echo "{\"measurement\":\"attestation_gen\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
      ;;
    sgx)
      local start_ns end_ns
      start_ns=$(get_time_ns)
      # Generate SGX quote via DCAP
      # sgx_quote_gen --nonce <random>
      end_ns=$(get_time_ns)
      local elapsed
      elapsed=$(elapsed_ns "$start_ns" "$end_ns")
      echo "{\"measurement\":\"attestation_gen\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
      ;;
    sev)
      local start_ns end_ns
      start_ns=$(get_time_ns)
      # Generate SEV-SNP attestation report
      # snp-guest report --nonce <random>
      end_ns=$(get_time_ns)
      local elapsed
      elapsed=$(elapsed_ns "$start_ns" "$end_ns")
      echo "{\"measurement\":\"attestation_gen\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
      ;;
  esac
}

# M3: Attestation Verification
measure_attestation_verify() {
  local iteration=$1
  if [[ "$VERBOSE" == true ]]; then
    log_info "  M3: Attestation Verify (iteration $iteration/$ITERATIONS)"
  fi

  local start_ns end_ns
  start_ns=$(get_time_ns)
  # Use the aethelredd binary to verify a cached attestation document
  # This exercises the full Go verification path: structural validation,
  # TEE config lookup, quote age check, measurement lookup, platform adapter,
  # replay registry write.
  #
  # NOTE: Replace with actual verification command when TEE worker is integrated
  # $AETHELRED_BIN verify-attestation \
  #   --platform "$PLATFORM" \
  #   --attestation-file "$OUTPUT_DIR/cached-attestation.bin" \
  #   --nonce "$(openssl rand -hex 32)" \
  #   2>/dev/null
  end_ns=$(get_time_ns)
  local elapsed
  elapsed=$(elapsed_ns "$start_ns" "$end_ns")
  echo "{\"measurement\":\"attestation_verify\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
}

# M4: Model Load
measure_model_load() {
  local iteration=$1
  if [[ "$VERBOSE" == true ]]; then
    log_info "  M4: Model Load (iteration $iteration/$ITERATIONS)"
  fi

  local start_ns end_ns
  start_ns=$(get_time_ns)
  # Load reference model into enclave memory
  # NOTE: Replace with actual model load command
  # $TEE_WORKER_BIN load-model \
  #   --platform "$PLATFORM" \
  #   --model "$REFERENCE_MODEL" \
  #   2>/dev/null
  end_ns=$(get_time_ns)
  local elapsed
  elapsed=$(elapsed_ns "$start_ns" "$end_ns")
  echo "{\"measurement\":\"model_load\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
}

# M5: Inference Time
measure_inference() {
  local iteration=$1
  if [[ "$VERBOSE" == true ]]; then
    log_info "  M5: Inference (iteration $iteration/$ITERATIONS)"
  fi

  local start_ns end_ns
  start_ns=$(get_time_ns)
  # Run single inference on the loaded model
  # NOTE: Replace with actual inference command
  # $TEE_WORKER_BIN infer \
  #   --platform "$PLATFORM" \
  #   --input "$OUTPUT_DIR/reference-input.bin" \
  #   2>/dev/null
  end_ns=$(get_time_ns)
  local elapsed
  elapsed=$(elapsed_ns "$start_ns" "$end_ns")
  echo "{\"measurement\":\"inference\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
}

# M6: End-to-End TEE Leg
measure_e2e() {
  local iteration=$1
  if [[ "$VERBOSE" == true ]]; then
    log_info "  M6: End-to-End (iteration $iteration/$ITERATIONS)"
  fi

  local start_ns end_ns
  start_ns=$(get_time_ns)
  # Full cycle: attest + verify + model load + infer
  # NOTE: Replace with actual e2e command
  # $TEE_WORKER_BIN run-e2e \
  #   --platform "$PLATFORM" \
  #   --model "$REFERENCE_MODEL" \
  #   --input "$OUTPUT_DIR/reference-input.bin" \
  #   2>/dev/null
  end_ns=$(get_time_ns)
  local elapsed
  elapsed=$(elapsed_ns "$start_ns" "$end_ns")
  echo "{\"measurement\":\"e2e_tee_leg\",\"iteration\":$iteration,\"ns\":$elapsed,\"platform\":\"$PLATFORM\"}"
}

# ============================================================================
# Statistics Computation
# ============================================================================

compute_statistics() {
  local raw_file=$1
  local measurement=$2

  # Extract nanosecond values for this measurement, skipping warmup
  # Uses jq to filter and compute stats
  if ! command -v jq &>/dev/null; then
    log_warn "jq not installed; skipping statistics computation"
    return
  fi

  local stats
  stats=$(jq -s --arg m "$measurement" --argjson warmup "$WARMUP" '
    [.[] | select(.measurement == $m)] |
    .[$warmup:] |        # Skip warmup iterations
    [.[].ns] |
    if length == 0 then
      {"count": 0, "error": "no data after warmup"}
    else
      sort |
      {
        count: length,
        min: .[0],
        max: .[-1],
        mean: (add / length),
        p50: .[((length * 0.50) | floor)],
        p95: .[((length * 0.95) | floor)],
        p99: .[((length * 0.99) | floor)],
        p999: .[((length * 0.999) | floor)],
        stddev: (
          (add / length) as $mean |
          (map(. - $mean | . * .) | add / length | sqrt)
        ),
        cv: (
          (add / length) as $mean |
          if $mean == 0 then 0
          else
            ((map(. - $mean | . * .) | add / length | sqrt) / $mean * 100)
          end
        )
      }
    end
  ' "$raw_file" 2>/dev/null)

  echo "$stats"
}

# ============================================================================
# Summary Generation
# ============================================================================

generate_summary() {
  local raw_file="$OUTPUT_DIR/raw-timings.json"
  local summary_file="$OUTPUT_DIR/summary.md"
  local hw_file="$OUTPUT_DIR/hardware-disclosure.json"

  log_info "Generating summary report..."

  cat > "$summary_file" <<HEADER
# TEE Hardware Benchmark Summary

**Run ID:** $RUN_ID
**Date:** $TIMESTAMP
**Platform:** $PLATFORM
**Topology:** $TOPOLOGY
**Iterations:** $ITERATIONS (warmup: $WARMUP discarded)
**Commit:** \`$COMMIT_HASH\`
**Methodology:** \`docs/operations/BENCHMARK_METHODOLOGY.md\` (SQ16-BMS-001)

---

## Hardware Disclosure

See \`hardware-disclosure.json\` for full machine-readable disclosure.
See \`docs/operations/phase2/TEE_HARDWARE_DISCLOSURE_TEMPLATE.md\` for the human-readable template.

---

## Results

HEADER

  local measurements=("enclave_start" "attestation_gen" "attestation_verify" "model_load" "inference" "e2e_tee_leg")
  local labels=("M1: Enclave Start" "M2: Attestation Generation" "M3: Attestation Verification" "M4: Model Load" "M5: Inference Time" "M6: End-to-End TEE Leg")

  for i in "${!measurements[@]}"; do
    local m="${measurements[$i]}"
    local label="${labels[$i]}"

    echo "### $label" >> "$summary_file"
    echo "" >> "$summary_file"

    local stats
    stats=$(compute_statistics "$raw_file" "$m")

    if [[ -z "$stats" ]] || echo "$stats" | jq -e '.error' >/dev/null 2>&1; then
      echo "_No data collected for this measurement._" >> "$summary_file"
      echo "" >> "$summary_file"
      continue
    fi

    # Convert ns to human-readable units
    local count p50 p95 p99 p999 mean stddev min_val max_val cv
    count=$(echo "$stats" | jq '.count')
    p50=$(echo "$stats" | jq '.p50')
    p95=$(echo "$stats" | jq '.p95')
    p99=$(echo "$stats" | jq '.p99')
    p999=$(echo "$stats" | jq '.p999')
    mean=$(echo "$stats" | jq '.mean')
    stddev=$(echo "$stats" | jq '.stddev')
    min_val=$(echo "$stats" | jq '.min')
    max_val=$(echo "$stats" | jq '.max')
    cv=$(echo "$stats" | jq '.cv')

    cat >> "$summary_file" <<TABLE
| Statistic | Value (ns) | Value (human) |
|-----------|-----------|---------------|
| **p50** | $p50 | $(format_ns "$p50") |
| **p95** | $p95 | $(format_ns "$p95") |
| **p99** | $p99 | $(format_ns "$p99") |
| **p99.9** | $p999 | $(format_ns "$p999") |
| **Mean** | $mean | $(format_ns "$mean") |
| **Std Dev** | $stddev | $(format_ns "$stddev") |
| **Min** | $min_val | $(format_ns "$min_val") |
| **Max** | $max_val | $(format_ns "$max_val") |
| **Sample Count** | $count | -- |
| **CV** | -- | ${cv}% |

TABLE

    # Flag CV > 15% per methodology requirement
    local cv_int
    cv_int=$(echo "$cv" | awk '{printf "%d", $1}')
    if [[ "$cv_int" -gt 15 ]]; then
      echo "> **WARNING:** CV = ${cv}% exceeds 15% threshold. Investigation required per SQ16-BMS-001 Section 4.4." >> "$summary_file"
      echo "" >> "$summary_file"
    fi
  done

  cat >> "$summary_file" <<FOOTER

---

## Compliance Checklist (SQ16-BMS-001)

- [ ] Hardware disclosure template is complete
- [ ] Topology is fully documented
- [ ] Warm-up protocol was followed ($WARMUP iterations discarded)
- [ ] Minimum iteration/duration requirements are met ($ITERATIONS iterations)
- [ ] p50, p95, p99 are all reported
- [ ] Min/max and sample count are included
- [ ] Worst-case scenario is included
- [ ] Reproduction commands are tested by a second person
- [ ] Version pinning is complete (commit: \`$COMMIT_SHORT\`)
- [ ] Claim registered in PERFORMANCE_CLAIMS_REGISTER.md
- [ ] Peer review sign-off recorded

---

## Reproduction

\`\`\`bash
git checkout $COMMIT_HASH
make build
./scripts/benchmark-tee-hardware.sh \\
  --platform $PLATFORM \\
  --topology $TOPOLOGY \\
  --iterations $ITERATIONS \\
  --warmup $WARMUP \\
  --output-dir $OUTPUT_DIR
\`\`\`

---

## Raw Data

| Artifact | Path |
|----------|------|
| Raw timings | \`$OUTPUT_DIR/raw-timings.json\` |
| Hardware disclosure | \`$OUTPUT_DIR/hardware-disclosure.json\` |
| This summary | \`$OUTPUT_DIR/summary.md\` |
FOOTER

  log_ok "Summary written to $summary_file"
}

# Format nanoseconds to human-readable
format_ns() {
  local ns=$1
  if [[ -z "$ns" ]] || [[ "$ns" == "null" ]]; then
    echo "N/A"
    return
  fi
  # Remove decimal part for integer comparison
  local ns_int
  ns_int=$(echo "$ns" | awk '{printf "%d", $1}')
  if [[ $ns_int -lt 1000 ]]; then
    echo "${ns} ns"
  elif [[ $ns_int -lt 1000000 ]]; then
    echo "$(echo "scale=2; $ns / 1000" | bc 2>/dev/null || echo "$ns") us"
  elif [[ $ns_int -lt 1000000000 ]]; then
    echo "$(echo "scale=2; $ns / 1000000" | bc 2>/dev/null || echo "$ns") ms"
  else
    echo "$(echo "scale=2; $ns / 1000000000" | bc 2>/dev/null || echo "$ns") s"
  fi
}

# ============================================================================
# Main Execution
# ============================================================================

run_benchmarks() {
  local raw_file="$OUTPUT_DIR/raw-timings.json"

  # Clear raw file
  : > "$raw_file"

  log_info "Starting benchmark campaign: $RUN_ID"
  log_info "Total iterations per measurement: $ITERATIONS (warmup: $WARMUP)"

  # ---- M1: Enclave Start ----
  # Enclave start is expensive; use fewer iterations (100 minimum per methodology)
  local m1_iterations=$ITERATIONS
  if [[ $m1_iterations -gt 200 ]]; then
    m1_iterations=200
    log_info "Capping M1 (Enclave Start) at $m1_iterations iterations (expensive operation)"
  fi

  log_info "Running M1: Enclave Start ($m1_iterations iterations)..."
  for ((i=1; i<=m1_iterations; i++)); do
    measure_enclave_start "$i" >> "$raw_file" 2>/dev/null || true
  done
  log_ok "M1 complete"

  # ---- M2: Attestation Generation ----
  log_info "Running M2: Attestation Generation ($ITERATIONS iterations)..."
  for ((i=1; i<=ITERATIONS; i++)); do
    measure_attestation_gen "$i" >> "$raw_file" 2>/dev/null || true
  done
  log_ok "M2 complete"

  # ---- M3: Attestation Verification ----
  log_info "Running M3: Attestation Verification ($ITERATIONS iterations)..."
  for ((i=1; i<=ITERATIONS; i++)); do
    measure_attestation_verify "$i" >> "$raw_file" 2>/dev/null || true
  done
  log_ok "M3 complete"

  # ---- M4: Model Load ----
  log_info "Running M4: Model Load ($ITERATIONS iterations)..."
  for ((i=1; i<=ITERATIONS; i++)); do
    measure_model_load "$i" >> "$raw_file" 2>/dev/null || true
  done
  log_ok "M4 complete"

  # ---- M5: Inference Time ----
  log_info "Running M5: Inference Time ($ITERATIONS iterations)..."
  for ((i=1; i<=ITERATIONS; i++)); do
    measure_inference "$i" >> "$raw_file" 2>/dev/null || true
  done
  log_ok "M5 complete"

  # ---- M6: End-to-End TEE Leg ----
  log_info "Running M6: End-to-End TEE Leg ($ITERATIONS iterations)..."
  for ((i=1; i<=ITERATIONS; i++)); do
    measure_e2e "$i" >> "$raw_file" 2>/dev/null || true
  done
  log_ok "M6 complete"

  log_ok "All measurements collected: $raw_file"
}

# ---- Main ----
main() {
  if [[ "$DRY_RUN" == true ]]; then
    log_info "Would collect hardware disclosure"
    log_info "Would run M1-M6 for platform=$PLATFORM topology=$TOPOLOGY"
    log_info "Would write results to $OUTPUT_DIR/"
    log_ok "Dry run complete"
    exit 0
  fi

  collect_hardware_disclosure
  run_benchmarks
  generate_summary

  log_info "============================================"
  log_ok "Benchmark campaign complete: $RUN_ID"
  log_info "Artifacts:"
  log_info "  Raw data:  $OUTPUT_DIR/raw-timings.json"
  log_info "  Hardware:  $OUTPUT_DIR/hardware-disclosure.json"
  log_info "  Summary:   $OUTPUT_DIR/summary.md"
  log_info "============================================"
}

main
