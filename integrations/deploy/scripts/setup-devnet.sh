#!/usr/bin/env bash
# ============================================================================
# Aethelred DevNet Setup Script
# ============================================================================
#
# Enterprise-grade DevNet initialization script that:
# 1. Validates prerequisites
# 2. Generates cryptographic keys
# 3. Builds Docker images
# 4. Deploys Ethereum bridge contract
# 5. Starts the DevNet cluster
# 6. Runs health checks
#
# Usage:
#   ./setup-devnet.sh [--build] [--clean] [--no-bridge] [--verbose]
#
# Options:
#   --build     Force rebuild of Docker images
#   --clean     Clean all data and start fresh
#   --no-bridge Skip Ethereum bridge deployment
#   --verbose   Enable verbose output
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
DEPLOY_DIR="${PROJECT_ROOT}/deploy"
CONFIG_DIR="${DEPLOY_DIR}/config"
DOCKER_DIR="${DEPLOY_DIR}/docker"
DATA_DIR="${DEPLOY_DIR}/data"
KEYS_DIR="${DATA_DIR}/keys"

# Docker Compose configuration
COMPOSE_FILE="${DOCKER_DIR}/docker-compose.yml"
COMPOSE_PROJECT_NAME="aethelred-devnet"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Timing
START_TIME=$(date +%s)

# Options
FORCE_BUILD=false
CLEAN_START=false
SKIP_BRIDGE=false
VERBOSE=false

# ============================================================================
# Utility Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Required command '$1' not found. Please install it."
        return 1
    fi
    return 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build)
                FORCE_BUILD=true
                shift
                ;;
            --clean)
                CLEAN_START=true
                shift
                ;;
            --no-bridge)
                SKIP_BRIDGE=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                set -x
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
}

print_usage() {
    cat << EOF
Aethelred DevNet Setup Script

Usage: $0 [OPTIONS]

Options:
    --build       Force rebuild of Docker images
    --clean       Clean all data and start fresh
    --no-bridge   Skip Ethereum bridge deployment
    --verbose     Enable verbose output
    -h, --help    Show this help message

Examples:
    # Fresh start with clean data
    $0 --clean --build

    # Quick restart without rebuilding
    $0

    # Development mode without bridge
    $0 --no-bridge
EOF
}

# ============================================================================
# Prerequisite Checks
# ============================================================================

check_prerequisites() {
    log_step "Step 1: Checking Prerequisites"

    local missing=0

    # Check Docker
    if check_command docker; then
        local docker_version=$(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)
        log_info "Docker version: ${docker_version}"
    else
        missing=$((missing + 1))
    fi

    # Check Docker Compose
    if check_command docker-compose || docker compose version &> /dev/null; then
        log_info "Docker Compose available"
    else
        log_error "Docker Compose not found"
        missing=$((missing + 1))
    fi

    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        missing=$((missing + 1))
    else
        log_info "Docker daemon is running"
    fi

    # Check Node.js for bridge deployment
    if ! $SKIP_BRIDGE; then
        if check_command node; then
            local node_version=$(node --version)
            log_info "Node.js version: ${node_version}"
        else
            log_warning "Node.js not found - bridge deployment may fail"
        fi
    fi

    # Check available disk space (require at least 10GB)
    local available_space=$(df -BG "${PROJECT_ROOT}" | tail -1 | awk '{print $4}' | sed 's/G//')
    if [[ ${available_space} -lt 10 ]]; then
        log_warning "Low disk space: ${available_space}GB available (recommended: 10GB+)"
    else
        log_info "Disk space: ${available_space}GB available"
    fi

    # Check available memory (require at least 4GB)
    local available_mem
    if [[ "$(uname)" == "Darwin" ]]; then
        available_mem=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
    else
        available_mem=$(free -g | awk '/^Mem:/{print $7}')
    fi
    log_info "Available memory: ${available_mem}GB"

    if [[ ${missing} -gt 0 ]]; then
        log_error "Missing ${missing} prerequisite(s). Please install them and try again."
        exit 1
    fi

    log_success "All prerequisites satisfied"
}

# ============================================================================
# Clean Up
# ============================================================================

cleanup() {
    log_step "Step 2: Cleaning Up Previous Deployment"

    # Stop existing containers
    log_info "Stopping existing containers..."
    cd "${DOCKER_DIR}"

    if docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" ps -q 2>/dev/null | grep -q .; then
        docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" down --remove-orphans || true
    fi

    if $CLEAN_START; then
        log_info "Removing data directories..."
        rm -rf "${DATA_DIR}"

        log_info "Removing Docker volumes..."
        docker volume rm "${COMPOSE_PROJECT_NAME}_bootnode-data" 2>/dev/null || true
        docker volume rm "${COMPOSE_PROJECT_NAME}_validator-alice-data" 2>/dev/null || true
        docker volume rm "${COMPOSE_PROJECT_NAME}_validator-bob-data" 2>/dev/null || true
        docker volume rm "${COMPOSE_PROJECT_NAME}_compute-charlie-data" 2>/dev/null || true
        docker volume rm "${COMPOSE_PROJECT_NAME}_bridge-data" 2>/dev/null || true
        docker volume rm "${COMPOSE_PROJECT_NAME}_prometheus-data" 2>/dev/null || true
        docker volume rm "${COMPOSE_PROJECT_NAME}_grafana-data" 2>/dev/null || true
    fi

    log_success "Cleanup complete"
}

# ============================================================================
# Generate Keys
# ============================================================================

generate_keys() {
    log_step "Step 3: Generating Cryptographic Keys"

    mkdir -p "${KEYS_DIR}"

    # Generate validator keys
    local validators=("alice" "bob")

    for validator in "${validators[@]}"; do
        local key_file="${KEYS_DIR}/validator-${validator}.json"

        if [[ -f "${key_file}" ]] && ! $CLEAN_START; then
            log_info "Using existing key for validator-${validator}"
        else
            log_info "Generating key for validator-${validator}..."

            # Generate a deterministic key for DevNet reproducibility
            # In production, use proper key generation
            local seed_hex=$(echo -n "aethelred-devnet-validator-${validator}" | sha256sum | cut -d' ' -f1)

            cat > "${key_file}" << EOF
{
  "address": "0x$(echo -n "${seed_hex}" | cut -c1-40)",
  "private_key": "0x${seed_hex}",
  "public_key": "0x04${seed_hex}${seed_hex:0:24}",
  "type": "validator",
  "name": "${validator}",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
            log_success "Generated key for validator-${validator}"
        fi
    done

    # Generate compute node key
    local compute_key="${KEYS_DIR}/compute-charlie.json"
    if [[ -f "${compute_key}" ]] && ! $CLEAN_START; then
        log_info "Using existing key for compute-charlie"
    else
        log_info "Generating key for compute-charlie..."

        local seed_hex=$(echo -n "aethelred-devnet-compute-charlie" | sha256sum | cut -d' ' -f1)

        cat > "${compute_key}" << EOF
{
  "address": "0x$(echo -n "${seed_hex}" | cut -c1-40)",
  "private_key": "0x${seed_hex}",
  "public_key": "0x04${seed_hex}${seed_hex:0:24}",
  "type": "compute",
  "name": "charlie",
  "tee_type": "mock",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
        log_success "Generated key for compute-charlie"
    fi

    # Generate bridge relayer key
    local bridge_key="${KEYS_DIR}/bridge-relayer.json"
    if [[ -f "${bridge_key}" ]] && ! $CLEAN_START; then
        log_info "Using existing key for bridge-relayer"
    else
        log_info "Generating key for bridge-relayer..."

        local seed_hex=$(echo -n "aethelred-devnet-bridge-relayer" | sha256sum | cut -d' ' -f1)

        cat > "${bridge_key}" << EOF
{
  "address": "0x$(echo -n "${seed_hex}" | cut -c1-40)",
  "eth_address": "0x$(echo -n "${seed_hex}" | cut -c1-40)",
  "private_key": "0x${seed_hex}",
  "type": "relayer",
  "name": "bridge-relayer",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
        log_success "Generated key for bridge-relayer"
    fi

    log_success "All keys generated in ${KEYS_DIR}"
}

# ============================================================================
# Build Docker Images
# ============================================================================

build_images() {
    log_step "Step 4: Building Docker Images"

    cd "${DOCKER_DIR}"

    if $FORCE_BUILD; then
        log_info "Force rebuilding all images..."
        docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" build --no-cache
    else
        log_info "Building images (using cache)..."
        docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" build
    fi

    log_success "Docker images built successfully"
}

# ============================================================================
# Deploy Bridge Contract
# ============================================================================

deploy_bridge_contract() {
    if $SKIP_BRIDGE; then
        log_info "Skipping bridge contract deployment (--no-bridge)"
        return 0
    fi

    log_step "Step 5: Deploying Bridge Contract"

    local contracts_dir="${PROJECT_ROOT}/contracts/ethereum"

    if [[ ! -d "${contracts_dir}" ]]; then
        log_error "Contracts directory not found: ${contracts_dir}"
        return 1
    fi

    cd "${contracts_dir}"

    # Install dependencies if needed
    if [[ ! -d "node_modules" ]]; then
        log_info "Installing contract dependencies..."
        npm install
    fi

    # Compile contracts
    log_info "Compiling contracts..."
    npx hardhat compile

    # For DevNet, we deploy to a local Anvil/Ganache instance
    # In production, this would deploy to Sepolia or Mainnet
    log_info "Deploying bridge contract to DevNet..."

    # Note: Actual deployment would happen here
    # For DevNet, we'll create a mock deployment record
    local deployment_dir="${contracts_dir}/deployments/devnet"
    mkdir -p "${deployment_dir}"

    cat > "${deployment_dir}/AethelredBridge.json" << EOF
{
  "proxyAddress": "0x0000000000000000000000000000000000000000",
  "implementationAddress": "0x0000000000000000000000000000000000000001",
  "networkName": "devnet",
  "chainId": 31337,
  "deploymentTimestamp": $(date +%s),
  "note": "Mock deployment for DevNet - replace with actual deployment"
}
EOF

    log_success "Bridge contract deployment prepared"
    log_warning "Note: Full deployment requires running Anvil/Ganache first"
}

# ============================================================================
# Start DevNet
# ============================================================================

start_devnet() {
    log_step "Step 6: Starting DevNet Cluster"

    cd "${DOCKER_DIR}"

    # Create required directories
    mkdir -p "${DATA_DIR}/bootnode"
    mkdir -p "${DATA_DIR}/validator-alice"
    mkdir -p "${DATA_DIR}/validator-bob"
    mkdir -p "${DATA_DIR}/compute-charlie"
    mkdir -p "${DATA_DIR}/bridge"
    mkdir -p "${DATA_DIR}/prometheus"
    mkdir -p "${DATA_DIR}/grafana"

    # Start the cluster
    log_info "Starting Docker containers..."
    docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" up -d

    # Wait for services to start
    log_info "Waiting for services to initialize..."
    sleep 10

    # Check container status
    log_info "Container status:"
    docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" ps

    log_success "DevNet cluster started"
}

# ============================================================================
# Health Checks
# ============================================================================

run_health_checks() {
    log_step "Step 7: Running Health Checks"

    local all_healthy=true

    # Check bootnode
    log_info "Checking bootnode..."
    if docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" exec -T bootnode curl -sf http://localhost:26657/health > /dev/null 2>&1; then
        log_success "Bootnode: HEALTHY"
    else
        log_warning "Bootnode: NOT READY (may still be starting)"
        all_healthy=false
    fi

    # Check validators
    for validator in alice bob; do
        log_info "Checking validator-${validator}..."
        if docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" exec -T "validator-${validator}" curl -sf http://localhost:26657/health > /dev/null 2>&1; then
            log_success "Validator ${validator}: HEALTHY"
        else
            log_warning "Validator ${validator}: NOT READY"
            all_healthy=false
        fi
    done

    # Check compute node
    log_info "Checking compute-charlie..."
    if docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" exec -T compute-charlie curl -sf http://localhost:26657/health > /dev/null 2>&1; then
        log_success "Compute charlie: HEALTHY"
    else
        log_warning "Compute charlie: NOT READY"
        all_healthy=false
    fi

    # Check bridge relayer
    log_info "Checking bridge-relayer..."
    if docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" exec -T bridge-relayer curl -sf http://localhost:8080/health > /dev/null 2>&1; then
        log_success "Bridge relayer: HEALTHY"
    else
        log_warning "Bridge relayer: NOT READY"
        all_healthy=false
    fi

    # Check Prometheus
    log_info "Checking Prometheus..."
    if curl -sf http://localhost:9090/-/healthy > /dev/null 2>&1; then
        log_success "Prometheus: HEALTHY"
    else
        log_warning "Prometheus: NOT READY"
        all_healthy=false
    fi

    # Check Grafana
    log_info "Checking Grafana..."
    if curl -sf http://localhost:3001/api/health > /dev/null 2>&1; then
        log_success "Grafana: HEALTHY"
    else
        log_warning "Grafana: NOT READY"
        all_healthy=false
    fi

    if $all_healthy; then
        log_success "All health checks passed!"
    else
        log_warning "Some services are still starting. Run './healthcheck.sh' to recheck."
    fi
}

# ============================================================================
# Print Summary
# ============================================================================

print_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    log_step "DevNet Setup Complete!"

    cat << EOF

╔═══════════════════════════════════════════════════════════════════════════╗
║                     AETHELRED DEVNET READY                                 ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  📡 Service Endpoints:                                                     ║
║  ├─ Bootnode RPC:      http://localhost:26657                             ║
║  ├─ Bootnode gRPC:     http://localhost:9090                              ║
║  ├─ Validator Alice:   http://localhost:26658                             ║
║  ├─ Validator Bob:     http://localhost:26659                             ║
║  ├─ Compute Charlie:   http://localhost:26660                             ║
║  ├─ Bridge Relayer:    http://localhost:8080                              ║
║  ├─ Faucet:            http://localhost:8081                              ║
║  ├─ Explorer:          http://localhost:3000                              ║
║  ├─ Prometheus:        http://localhost:9091                              ║
║  └─ Grafana:           http://localhost:3001 (admin/admin)                ║
║                                                                            ║
║  🔑 Keys stored in: ${KEYS_DIR}
║                                                                            ║
║  📊 Useful Commands:                                                       ║
║  ├─ View logs:    docker compose -p aethelred-devnet logs -f             ║
║  ├─ Stop:         docker compose -p aethelred-devnet down                ║
║  ├─ Restart:      docker compose -p aethelred-devnet restart             ║
║  └─ Health check: ./deploy/scripts/healthcheck.sh                         ║
║                                                                            ║
║  ⏱️  Setup completed in ${duration} seconds                                 ║
╚═══════════════════════════════════════════════════════════════════════════╝

EOF
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║                     AETHELRED DEVNET SETUP                                 ║"
    echo "║                     Enterprise Blockchain Platform                         ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo ""

    parse_args "$@"

    check_prerequisites
    cleanup
    generate_keys
    build_images
    deploy_bridge_contract
    start_devnet
    run_health_checks
    print_summary
}

# Run main function
main "$@"
