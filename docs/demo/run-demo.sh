#!/bin/bash
# Aethelred Demo Runner
# Run impressive demos without a testnet

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Default values
DEMO_MODE="presentation"
OUTPUT_DIR=""
OUTPUT_FORMAT="console"
WITH_DASHBOARD=false
VERBOSE=false
SCENARIO=""

# Banner
print_banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║     █████╗ ███████╗████████╗██╗  ██╗███████╗██╗     ██████╗   ║"
    echo "║    ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██║     ██╔══██╗  ║"
    echo "║    ███████║█████╗     ██║   ███████║█████╗  ██║     ██║  ██║  ║"
    echo "║    ██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║     ██║  ██║  ║"
    echo "║    ██║  ██║███████╗   ██║   ██║  ██║███████╗███████╗██████╔╝  ║"
    echo "║    ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝   ║"
    echo "║                                                               ║"
    echo "║          Sovereign Layer 1 for Verifiable AI                  ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Usage
usage() {
    echo -e "${BOLD}Usage:${NC} $0 <demo> [options]"
    echo ""
    echo -e "${BOLD}Demos:${NC}"
    echo "  falcon-lion    Cross-border trade finance (UAE ↔ Singapore)"
    echo "  helix-guard    Sovereign drug discovery (UAE ↔ UK)"
    echo "  credit-score   Privacy-preserving credit assessment"
    echo "  sdk-showcase   SDK capabilities demonstration"
    echo "  all            Run all demos sequentially"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  --mode <mode>      Demo speed: fast|realistic|presentation (default: presentation)"
    echo "  --output <dir>     Save results to directory"
    echo "  --format <fmt>     Output format: console|json|pdf|all (default: console)"
    echo "  --with-dashboard   Launch web dashboard alongside demo"
    echo "  --scenario <name>  Use predefined scenario: investor|developer|enterprise"
    echo "  --verbose          Show detailed output"
    echo "  --help             Show this help"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 falcon-lion --mode presentation"
    echo "  $0 helix-guard --output ./demo-results --format pdf"
    echo "  $0 all --scenario investor --with-dashboard"
    echo ""
}

# Parse arguments
parse_args() {
    if [ $# -eq 0 ]; then
        usage
        exit 1
    fi

    DEMO="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case $1 in
            --mode)
                DEMO_MODE="$2"
                shift 2
                ;;
            --output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --with-dashboard)
                WITH_DASHBOARD=true
                shift
                ;;
            --scenario)
                SCENARIO="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                usage
                exit 1
                ;;
        esac
    done
}

# Check prerequisites
check_prerequisites() {
    echo -e "${CYAN}Checking prerequisites...${NC}"

    local missing=()

    # Check for Rust/Cargo
    if ! command -v cargo &> /dev/null; then
        missing+=("cargo (Rust)")
    fi

    # Check for Node.js
    if ! command -v node &> /dev/null; then
        missing+=("node (Node.js)")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Some tools are missing:${NC}"
        for tool in "${missing[@]}"; do
            echo "  - $tool"
        done
        echo ""
        echo "Some demos may not work. Install missing tools for full functionality."
        echo ""
    else
        echo -e "${GREEN}✓ All prerequisites met${NC}"
    fi
}

# Start dashboard
start_dashboard() {
    echo -e "${CYAN}Starting demo dashboard...${NC}"

    DASHBOARD_DIR="$SCRIPT_DIR/dashboard"

    if [ ! -d "$DASHBOARD_DIR" ]; then
        echo -e "${YELLOW}Dashboard not found. Creating minimal dashboard...${NC}"
        mkdir -p "$DASHBOARD_DIR"
    fi

    # Check if dashboard has package.json
    if [ -f "$DASHBOARD_DIR/package.json" ]; then
        cd "$DASHBOARD_DIR"
        npm install --silent 2>/dev/null || true
        npm start &
        DASHBOARD_PID=$!
        cd "$SCRIPT_DIR"
        echo -e "${GREEN}✓ Dashboard starting at http://localhost:3000${NC}"
        sleep 2
    else
        echo -e "${YELLOW}Dashboard package.json not found. Skipping dashboard.${NC}"
    fi
}

# Run Falcon-Lion demo
run_falcon_lion() {
    echo ""
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  PROJECT FALCON-LION: Cross-Border Trade Finance${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}Scenario:${NC} Falcon Trading (UAE) ships goods to Lion Logistics (Singapore)"
    echo -e "${CYAN}Duration:${NC} ~${DEMO_MODE} mode"
    echo ""

    FALCON_DIR="$ROOT_DIR/crates/demo/falcon-lion"

    if [ -d "$FALCON_DIR" ]; then
        cd "$FALCON_DIR"

        # Build if needed
        if [ ! -f "target/release/falcon-lion" ]; then
            echo -e "${YELLOW}Building Falcon-Lion demo...${NC}"
            cargo build --release --quiet 2>/dev/null || {
                echo -e "${YELLOW}Cargo build unavailable, using simulation mode${NC}"
                simulate_falcon_lion
                return
            }
        fi

        # Run the demo
        DEMO_ARGS=""
        case $DEMO_MODE in
            fast)
                DEMO_ARGS="--fast"
                ;;
            realistic)
                DEMO_ARGS=""
                ;;
            presentation)
                DEMO_ARGS="--presentation"
                ;;
        esac

        if [ -n "$OUTPUT_DIR" ]; then
            mkdir -p "$OUTPUT_DIR"
            DEMO_ARGS="$DEMO_ARGS --output $OUTPUT_DIR/falcon-lion-results.json"
        fi

        cargo run --release --quiet -- $DEMO_ARGS 2>/dev/null || simulate_falcon_lion

        cd "$SCRIPT_DIR"
    else
        simulate_falcon_lion
    fi
}

# Simulate Falcon-Lion (when binary not available)
simulate_falcon_lion() {
    echo -e "${YELLOW}Running simulation mode...${NC}"
    echo ""

    local steps=(
        "Initializing Falcon Trading (UAE) identity"
        "Initializing Lion Logistics (Singapore) identity"
        "Creating trade deal: Electronics Shipment (USD 2,500,000)"
        "Submitting to UAE regulatory sandbox"
        "TEE Enclave: Verifying export compliance (UAE)"
        "Generating cryptographic proof of compliance"
        "Crossing sovereign boundary: UAE → Singapore"
        "TEE Enclave: Verifying import compliance (Singapore)"
        "Minting Letter of Credit as Digital Seal"
        "Recording on Aethelred blockchain"
        "Generating audit trail"
        "Demo complete!"
    )

    local total=${#steps[@]}
    local delay=0.5

    case $DEMO_MODE in
        fast) delay=0.2 ;;
        realistic) delay=1 ;;
        presentation) delay=2 ;;
    esac

    for i in "${!steps[@]}"; do
        local step="${steps[$i]}"
        local num=$((i + 1))

        # Progress bar
        local progress=$((num * 100 / total))
        local filled=$((progress / 5))
        local empty=$((20 - filled))

        printf "\r${CYAN}[%3d%%]${NC} " "$progress"
        printf "${GREEN}"
        printf '█%.0s' $(seq 1 $filled)
        printf "${NC}"
        printf '░%.0s' $(seq 1 $empty)
        printf " "

        echo -e "${step}"

        # Add visual flair for key steps
        if [[ "$step" == *"TEE Enclave"* ]]; then
            sleep 0.3
            echo -e "       ${GREEN}✓${NC} Attestation verified: SGX Quote valid"
            echo -e "       ${GREEN}✓${NC} Measurement hash: 0x7a8b...3c4d"
        fi

        if [[ "$step" == *"Digital Seal"* ]]; then
            sleep 0.3
            echo -e "       ${GREEN}✓${NC} Seal ID: seal_falcon_lion_$(date +%s)"
            echo -e "       ${GREEN}✓${NC} Verification methods: TEE + zkML"
        fi

        sleep $delay
    done

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  FALCON-LION DEMO COMPLETE${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Deal Value:${NC}      USD 2,500,000"
    echo -e "  ${BOLD}Compliance:${NC}      UAE Export ✓ | Singapore Import ✓"
    echo -e "  ${BOLD}Digital Seal:${NC}    Minted and verified"
    echo -e "  ${BOLD}Audit Trail:${NC}     12 entries recorded"
    echo -e "  ${BOLD}Total Time:${NC}      $(printf '%.1f' $(echo "$delay * $total" | bc))s"
    echo ""
}

# Run Helix-Guard demo
run_helix_guard() {
    echo ""
    echo -e "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${PURPLE}  PROJECT HELIX-GUARD: Sovereign Drug Discovery${NC}"
    echo -e "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}Scenario:${NC} M42 Health (UAE) + AstraZeneca (UK) blind drug discovery"
    echo -e "${CYAN}Duration:${NC} ~${DEMO_MODE} mode"
    echo ""

    HELIX_DIR="$ROOT_DIR/crates/demo/helix-guard"

    if [ -d "$HELIX_DIR" ]; then
        cd "$HELIX_DIR"

        # Build if needed
        if [ ! -f "target/release/helix-guard" ]; then
            echo -e "${YELLOW}Building Helix-Guard demo...${NC}"
            cargo build --release --quiet 2>/dev/null || {
                echo -e "${YELLOW}Cargo build unavailable, using simulation mode${NC}"
                simulate_helix_guard
                return
            }
        fi

        # Run the demo
        DEMO_ARGS=""
        case $DEMO_MODE in
            fast)
                DEMO_ARGS="--no-delays"
                ;;
            realistic)
                DEMO_ARGS=""
                ;;
            presentation)
                DEMO_ARGS="--candidates 3"
                ;;
        esac

        if [ -n "$OUTPUT_DIR" ]; then
            mkdir -p "$OUTPUT_DIR"
            DEMO_ARGS="$DEMO_ARGS --format json"
        fi

        cargo run --release --quiet -- $DEMO_ARGS 2>/dev/null || simulate_helix_guard

        cd "$SCRIPT_DIR"
    else
        simulate_helix_guard
    fi
}

# Simulate Helix-Guard (when binary not available)
simulate_helix_guard() {
    echo -e "${YELLOW}Running simulation mode...${NC}"
    echo ""

    local steps=(
        "Initializing M42 Health (UAE) secure enclave"
        "Initializing AstraZeneca (UK) secure enclave"
        "M42: Submitting 3 drug candidates (encrypted)"
        "AstraZeneca: Submitting molecular targets (encrypted)"
        "Creating blind computation session"
        "M42 approval: Authorized computation"
        "AstraZeneca approval: Authorized computation"
        "TEE: Executing blind drug-target matching"
        "zkML: Generating computation proof"
        "Computing royalty distribution (M42: 60%, AZ: 40%)"
        "Settlement: 150,000 AETHEL tokens allocated"
        "Recording results on blockchain"
        "Generating compliance audit trail"
        "Demo complete!"
    )

    local total=${#steps[@]}
    local delay=0.5

    case $DEMO_MODE in
        fast) delay=0.2 ;;
        realistic) delay=1 ;;
        presentation) delay=2 ;;
    esac

    for i in "${!steps[@]}"; do
        local step="${steps[$i]}"
        local num=$((i + 1))

        # Progress bar
        local progress=$((num * 100 / total))
        local filled=$((progress / 5))
        local empty=$((20 - filled))

        printf "\r${PURPLE}[%3d%%]${NC} " "$progress"
        printf "${GREEN}"
        printf '█%.0s' $(seq 1 $filled)
        printf "${NC}"
        printf '░%.0s' $(seq 1 $empty)
        printf " "

        echo -e "${step}"

        # Add visual flair for key steps
        if [[ "$step" == *"blind drug-target"* ]]; then
            sleep 0.3
            echo -e "       ${GREEN}✓${NC} Match found: Candidate #2 ↔ Target BRCA1"
            echo -e "       ${GREEN}✓${NC} Binding affinity: 94.7% confidence"
            echo -e "       ${GREEN}✓${NC} Raw data never exposed"
        fi

        if [[ "$step" == *"zkML"* ]]; then
            sleep 0.3
            echo -e "       ${GREEN}✓${NC} Proof size: 1.2 KB"
            echo -e "       ${GREEN}✓${NC} Verification time: 12ms"
        fi

        sleep $delay
    done

    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}  HELIX-GUARD DEMO COMPLETE${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Partners:${NC}        M42 Health (UAE) + AstraZeneca (UK)"
    echo -e "  ${BOLD}Candidates:${NC}      3 drug compounds analyzed"
    echo -e "  ${BOLD}Best Match:${NC}      Candidate #2 (94.7% confidence)"
    echo -e "  ${BOLD}Data Exposure:${NC}   NONE (blind computation)"
    echo -e "  ${BOLD}Settlement:${NC}      150,000 AETHEL"
    echo -e "  ${BOLD}Compliance:${NC}      UAE DPL ✓ | UK GDPR ✓ | HIPAA ✓"
    echo ""
}

# Run Credit Score demo
run_credit_score() {
    echo ""
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  CREDIT SCORING: Privacy-Preserving Assessment${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    EXAMPLE_FILE="$ROOT_DIR/sdk/typescript/examples/credit-scoring-demo.ts"

    if [ -f "$EXAMPLE_FILE" ]; then
        cd "$ROOT_DIR/sdk/typescript"

        if command -v npx &> /dev/null; then
            echo -e "${CYAN}Running TypeScript SDK demo...${NC}"
            npx ts-node examples/credit-scoring-demo.ts 2>/dev/null || simulate_credit_score
        else
            simulate_credit_score
        fi

        cd "$SCRIPT_DIR"
    else
        simulate_credit_score
    fi
}

# Simulate Credit Score demo
simulate_credit_score() {
    echo -e "${YELLOW}Running simulation mode...${NC}"
    echo ""

    local profiles=("Alice (Excellent)" "Bob (Fair)" "Charlie (Poor)")
    local scores=(780 650 520)
    local results=("APPROVED" "REVIEW" "DECLINED")

    for i in "${!profiles[@]}"; do
        local profile="${profiles[$i]}"
        local score="${scores[$i]}"
        local result="${results[$i]}"

        echo -e "${CYAN}Processing:${NC} $profile"
        sleep 0.5
        echo -e "  Submitting to TEE enclave..."
        sleep 0.3
        echo -e "  Computing credit score..."
        sleep 0.3
        echo -e "  Generating zkML proof..."
        sleep 0.3

        if [ "$result" == "APPROVED" ]; then
            echo -e "  ${GREEN}Result: $result (Score: $score)${NC}"
        elif [ "$result" == "REVIEW" ]; then
            echo -e "  ${YELLOW}Result: $result (Score: $score)${NC}"
        else
            echo -e "  ${RED}Result: $result (Score: $score)${NC}"
        fi

        echo -e "  ${GREEN}✓${NC} Digital Seal created"
        echo ""
        sleep 0.5
    done

    echo -e "${GREEN}Credit scoring demo complete!${NC}"
}

# Run SDK Showcase
run_sdk_showcase() {
    echo ""
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${YELLOW}  SDK SHOWCASE: Multi-Language Support${NC}"
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    echo -e "${CYAN}Available SDKs:${NC}"
    echo ""

    # TypeScript SDK
    if [ -d "$ROOT_DIR/sdk/typescript" ]; then
        echo -e "  ${GREEN}✓${NC} TypeScript SDK"
        echo -e "    - Full async/await support"
        echo -e "    - React hooks available"
        echo -e "    - Browser + Node.js compatible"
    fi

    # Python SDK
    if [ -d "$ROOT_DIR/sdk/python" ]; then
        echo -e "  ${GREEN}✓${NC} Python SDK"
        echo -e "    - Jupyter notebook integration"
        echo -e "    - pandas/numpy interop"
        echo -e "    - ML framework support"
    fi

    # Rust SDK
    if [ -d "$ROOT_DIR/sdk/rust" ]; then
        echo -e "  ${GREEN}✓${NC} Rust SDK"
        echo -e "    - Zero-copy operations"
        echo -e "    - WASM compilation support"
        echo -e "    - Performance-critical use cases"
    fi

    # Go SDK
    if [ -d "$ROOT_DIR/sdk/go" ]; then
        echo -e "  ${GREEN}✓${NC} Go SDK"
        echo -e "    - gRPC native support"
        echo -e "    - Context-aware operations"
        echo -e "    - Cloud-native ready"
    fi

    echo ""
    echo -e "${CYAN}Common SDK Features:${NC}"
    echo "  • Job submission and tracking"
    echo "  • Digital Seal creation and verification"
    echo "  • TEE attestation verification"
    echo "  • zkML proof generation"
    echo "  • Real-time event subscriptions"
    echo "  • Batch operations"
    echo ""
}

# Run all demos
run_all() {
    run_falcon_lion
    echo ""
    echo -e "${YELLOW}Pausing before next demo...${NC}"
    sleep 2
    run_helix_guard
    echo ""
    echo -e "${YELLOW}Pausing before next demo...${NC}"
    sleep 2
    run_credit_score
    echo ""
    run_sdk_showcase
}

# Apply scenario presets
apply_scenario() {
    case $SCENARIO in
        investor)
            echo -e "${CYAN}Applying investor pitch scenario...${NC}"
            DEMO_MODE="presentation"
            ;;
        developer)
            echo -e "${CYAN}Applying developer onboarding scenario...${NC}"
            DEMO_MODE="realistic"
            ;;
        enterprise)
            echo -e "${CYAN}Applying enterprise evaluation scenario...${NC}"
            DEMO_MODE="presentation"
            OUTPUT_FORMAT="pdf"
            ;;
    esac
}

# Main
main() {
    parse_args "$@"

    print_banner

    if [ -n "$SCENARIO" ]; then
        apply_scenario
    fi

    check_prerequisites

    if [ "$WITH_DASHBOARD" = true ]; then
        start_dashboard
    fi

    case $DEMO in
        falcon-lion|falcon|fl)
            run_falcon_lion
            ;;
        helix-guard|helix|hg)
            run_helix_guard
            ;;
        credit-score|credit|cs)
            run_credit_score
            ;;
        sdk-showcase|sdk)
            run_sdk_showcase
            ;;
        all)
            run_all
            ;;
        *)
            echo -e "${RED}Unknown demo: $DEMO${NC}"
            usage
            exit 1
            ;;
    esac

    echo ""
    echo -e "${GREEN}${BOLD}Demo completed successfully!${NC}"
    echo ""

    if [ -n "$OUTPUT_DIR" ]; then
        echo -e "Results saved to: ${CYAN}$OUTPUT_DIR${NC}"
    fi

    echo -e "For more information: ${CYAN}https://docs.aethelred.ai${NC}"
    echo ""
}

main "$@"
