# Makefile for Aethelred - Sovereign L1 for Verifiable AI
# The Digital Seal for Verifiable Intelligence
#
# ARCHITECTURE: This project has two independent runtime stacks:
#
#   Go Stack (Cosmos SDK)          Rust Stack (crates/)
#   ├── app/          ABCI++ app   ├── aethelred-core       Core crypto
#   ├── x/pouw/        PoUW module   ├── aethelred-consensus  VRF consensus
#   ├── x/seal/       Seal module  ├── aethelred-vm         WASM VM
#   ├── x/verify/     Verify mod   ├── aethelred-mempool    Mempool
#   └── cmd/          Node binary  ├── aethelred-bridge     Bridge relayer
#                                  └── falcon-lion          Trade demo
#
# Integration: HTTP/gRPC only (no FFI/CGo). Shared contract: proto/*.proto
# Go chain is source of truth. Rust services are stateless workers.

BINARY_NAME = aethelredd
BUILD_DIR = ./build
GO = go
# Rust uses a top-level vendor/ directory; force module mode for Go commands.
GOFLAGS ?= -mod=mod
GOCACHE ?= $(CURDIR)/.cache/go-build
LDFLAGS = -s -w -X github.com/aethelred/aethelred/app.Version=$(VERSION)

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Docker
DOCKER_IMAGE = aethelred/aethelredd
DOCKER_TAG = $(VERSION)

# Testnet
CHAIN_ID = aethelred-testnet-1
MONIKER = aethelred-node

.PHONY: all build install clean test lint fmt proto openapi openapi-validate docs docker help sdk-version-check sdk-release-check sdk-publish-dry-run audit-signoff-check loadtest loadtest-scenarios coverage-critical local-readiness validator-helm-validate public-testnet-readiness m42-pilot-pretestnet m42-sandbox-prepare m42-sandbox-preflight m42-sandbox-drill m42-pilot-gap-audit m42-pilot-go-live m42-sandbox-up m42-sandbox-down m42-sandbox-status m42-sandbox-logs m42-sandbox-validate m42-pin-images m42-conversion-docs m42-workloads-generate m42-workloads-score m42-test m42-verify m42-bench m42-realdata m42-verifiable-inference m42-attestation m42-sandbox-drill-all release-preflight fuzz-check

## help: Show this help message
help:
	@echo "Aethelred - The Digital Seal for Verifiable Intelligence"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'

## all: Build everything
all: build

## build: Build the aethelredd binary
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/aethelredd

## install: Install aethelredd to GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/aethelredd

## clean: Remove build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf ~/.aethelred

## test: Run all tests
test:
	@echo "Running tests..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v ./...

## test-unit: Run unit tests
test-unit:
	@echo "Running unit tests..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v -short ./...

## test-integration: Run integration tests
test-integration:
	@echo "Running integration tests..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v -run Integration ./...

## test-consensus: Run consensus-specific tests
test-consensus:
	@echo "Running consensus tests..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v ./app/... -run Consensus

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v -coverprofile=coverage.out ./...
	GOCACHE=$(GOCACHE) $(GO) tool cover -html=coverage.out -o coverage.html

## coverage-critical: Enforce >=95% average coverage for consensus/verification critical guardrails
coverage-critical:
	@python3 ./scripts/check_critical_coverage.py --threshold 95

## bench: Run benchmarks for core packages
bench:
	@echo "Running benchmarks..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -run=^$$ -bench=. -benchmem ./x/pouw/... ./x/verify/...

## bench-report: Run benchmarks and save a timestamped report
bench-report:
	@./scripts/run_benchmarks.sh

## loadtest: Run load test with default baseline settings
loadtest:
	@echo "Running baseline load test..."
	$(GO) run ./cmd/aethelred-loadtest --scenario baseline

## loadtest-scenarios: Run all predefined stress scenarios
loadtest-scenarios:
	@echo "Running all load test scenarios..."
	$(GO) run ./cmd/aethelred-loadtest --all-scenarios

FUZZ_CRATES = bridge/fuzz consensus/fuzz core/fuzz vm/fuzz

## fuzz-check: Type-check all fuzz crates (requires network; bypasses vendor source replacement)
fuzz-check:
	@echo "Checking fuzz crates (bypassing vendor source replacement)..."
	@for crate in $(FUZZ_CRATES); do \
		echo "  Checking crates/$$crate ..."; \
		mv .cargo/config.toml .cargo/config.toml.fuzz-bak 2>/dev/null; \
		mv crates/.cargo/config.toml crates/.cargo/config.toml.fuzz-bak 2>/dev/null; \
		cargo check --manifest-path crates/$$crate/Cargo.toml; \
		status=$$?; \
		mv .cargo/config.toml.fuzz-bak .cargo/config.toml 2>/dev/null; \
		mv crates/.cargo/config.toml.fuzz-bak crates/.cargo/config.toml 2>/dev/null; \
		if [ $$status -ne 0 ]; then exit $$status; fi; \
	done
	@echo "All fuzz crates compile cleanly."

## lint: Run linters
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: brew install golangci-lint"; \
	fi

## fmt: Format code
fmt:
	@echo "Formatting code..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

## proto: Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@./scripts/protocgen.sh

## openapi: Generate OpenAPI (Swagger) specification
openapi:
	@echo "Generating OpenAPI spec..."
	@./scripts/openapi_gen.sh

## openapi-validate: Generate and validate OpenAPI artifacts
openapi-validate: openapi
	@echo "Validating OpenAPI artifacts..."
	@test -f docs/api/openapi/aethelred.openapi.yaml
	@test -f docs/api/openapi/aethelred.swagger.json
	@jq . docs/api/openapi/aethelred.swagger.json >/dev/null
	@echo "OpenAPI validation passed."

## docs: Generate documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p $(GOCACHE)
	@GOCACHE=$(GOCACHE) $(GO) doc -all ./... > docs/api/godoc.txt

## sdk-version-check: Validate SDK/API versions against the matrix
sdk-version-check:
	@echo "Checking SDK/API version matrix..."
	@python3 ./scripts/check_sdk_versions.py

## sdk-release-check: Run SDK release gates (versions + OpenAPI)
sdk-release-check: sdk-version-check openapi-validate
	@echo "SDK release checks passed."

## sdk-publish-dry-run: Run local SDK publish dry-run (build/package only)
sdk-publish-dry-run:
	@./scripts/sdk_publish_dry_run.sh

## audit-signoff-check: Enforce completed external audit signoff for contracts + consensus
audit-signoff-check:
	@python3 ./scripts/check_contract_audit_signoff.py \
		--required-scope /contracts/ethereum \
		--required-scope "Consensus + vote extensions" \
		--require-signed-report

## local-readiness: Run lightweight audit, policy, and devnet guardrails
local-readiness:
	@python3 ./scripts/validate-repo-authority.py
	@python3 ./scripts/validate_canonical_product_truth.py
	@bash ./scripts/validate-compose-security.sh .
	@bash ./scripts/validate-pouw-medium-guards.sh .
	@bash ./scripts/validate-low-findings-guards.sh .
	@$(MAKE) devnet-validate
	@echo "Local readiness checks passed."

## validator-helm-validate: Lint and render-check the production validator Helm chart
validator-helm-validate:
	@bash ./scripts/validate-validator-helm-chart.sh

## public-testnet-readiness: Validate public testnet launch blockers and handoff consistency
public-testnet-readiness:
	@python3 ./scripts/validate-public-testnet-readiness.py

## finalize-testnet-genesis: Inject launch time, real node IDs, and bridge posture into the
## testnet genesis, recompute the checksum, sync the runbook/RC docs, and run the readiness gate.
## Pass launch parameters via ARGS, e.g.:
##   make finalize-testnet-genesis ARGS="--launch-in 48h --disable-bridge --seed <id>@host:26656 ..."
finalize-testnet-genesis:
	@python3 ./scripts/finalize-testnet-genesis.py $(ARGS)

## m42-pilot-pretestnet: Prepare local M42 pilot evidence dirs and run pre-testnet validation
m42-pilot-pretestnet:
	@bash ./scripts/validate-m42-pilot-pretestnet.sh

## m42-sandbox-prepare: Prepare dedicated M42 sandbox evidence dirs and local secrets
m42-sandbox-prepare:
	@bash ./scripts/m42-sandbox.sh prepare

## m42-sandbox-preflight: Validate the dedicated M42 sandbox package before services are live
m42-sandbox-preflight:
	@bash ./scripts/m42-sandbox.sh preflight

## m42-sandbox-drill: Generate M42 evidence/value drill artifacts for sponsor review (active workload)
m42-sandbox-drill:
	@bash ./scripts/m42-sandbox.sh drill

## m42-sandbox-drill-all: Generate drill evidence for all four M42 workloads plus catalog scorecard
m42-sandbox-drill-all:
	@python3 ./scripts/m42-sandbox-drill.py --all

## m42-workloads-generate: Regenerate the four M42 workload packs and synthetic fixtures
m42-workloads-generate:
	@python3 ./scripts/m42_workloads.py generate

## m42-workloads-score: Compute domain metrics for all workloads and enforce acceptance floors
m42-workloads-score:
	@python3 ./scripts/m42_workloads.py score

## m42-test: Run the M42 workload-platform test suite (metrics, statistics, evidence, catalog, crypto)
m42-test:
	@python3 -m pytest tests/m42 -q

## m42-verify: Independently verify every Digital Seal (the verifier M42 runs) + tamper demo
m42-verify:
	@python3 ./scripts/m42-verify.py --all --demo-tamper

## m42-bench: Benchmark Digital Seal throughput (validator fast path vs full audit) and PQC profile
m42-bench:
	@python3 ./scripts/m42-bench.py

## m42-realdata: Validate drug discovery on REAL ChEMBL EGFR data + verifiable seal
m42-realdata:
	@python3 ./scripts/m42-realdata-validate.py

## m42-verifiable-inference: Freivalds matmul verification of an LLM-scale layer + seal
m42-verifiable-inference:
	@python3 ./scripts/m42-verifiable-inference.py

## m42-attestation: Verify a real attestation from all six platforms + show the vendor/test-root boundary
m42-attestation:
	@go run ./cmd/aethelred-attestation-demo/

## m42-pilot-gap-audit: Generate M42 gap register, investor report, and sponsor evidence portal
m42-pilot-gap-audit:
	@bash ./scripts/m42-sandbox.sh gap-audit

## m42-pilot-go-live: Strict M42 go-live gate; fails on any open blocker
m42-pilot-go-live:
	@bash ./scripts/m42-sandbox.sh gap-audit-strict
	@bash ./scripts/m42-sandbox.sh validate

## m42-sandbox-up: Start the dedicated M42 pilot sandbox
m42-sandbox-up:
	@bash ./scripts/m42-sandbox.sh up

## m42-sandbox-down: Stop the dedicated M42 pilot sandbox
m42-sandbox-down:
	@bash ./scripts/m42-sandbox.sh down

## m42-sandbox-status: Show dedicated M42 pilot sandbox services
m42-sandbox-status:
	@bash ./scripts/m42-sandbox.sh status

## m42-sandbox-logs: Stream dedicated M42 pilot sandbox logs
m42-sandbox-logs:
	@bash ./scripts/m42-sandbox.sh logs

## m42-sandbox-validate: Validate live dedicated M42 sandbox endpoints and package
m42-sandbox-validate:
	@bash ./scripts/m42-sandbox.sh validate

## m42-pin-images: Resolve M42 sandbox image digests into config/pilots/m42/images.lock.env
m42-pin-images:
	@bash ./scripts/m42-sandbox.sh pin-images

## m42-conversion-docs: Regenerate M42 conversion deliverables (dossier/memo PDFs, LOI/MOU Word drafts, Tier-2 brief)
m42-conversion-docs:
	@python3 scripts/generate-m42-conversion-pdfs.py
	@python3 scripts/generate-m42-tier2-brief-pdf.py
	@NODE_PATH="$$(npm root -g)" node scripts/generate-m42-legal-drafts.js

## release-preflight: Run all pre-release validation checks
release-preflight: local-readiness validator-helm-validate audit-signoff-check coverage-critical sdk-version-check openapi-validate
	@echo "All release preflight checks passed"

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

## docker-push: Push Docker image
docker-push:
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest

## init: Initialize a new node
init:
	@echo "Initializing $(MONIKER) on chain $(CHAIN_ID)..."
	$(BUILD_DIR)/$(BINARY_NAME) init $(MONIKER) --chain-id $(CHAIN_ID)

## genesis: Create genesis file
genesis:
	@echo "Creating genesis file..."
	$(BUILD_DIR)/$(BINARY_NAME) add-genesis-account $(shell $(BUILD_DIR)/$(BINARY_NAME) keys show validator -a) 1000000000uaeth
	$(BUILD_DIR)/$(BINARY_NAME) gentx validator 100000000uaeth --chain-id $(CHAIN_ID)
	$(BUILD_DIR)/$(BINARY_NAME) collect-gentxs

## start: Start a single node
start: build
	@echo "Starting $(BINARY_NAME)..."
	$(BUILD_DIR)/$(BINARY_NAME) start

## testnet-start: Start local testnet (3 validators)
testnet-start: build
	@echo "Starting local testnet..."
	@./scripts/testnet.sh start

## testnet-stop: Stop local testnet
testnet-stop:
	@echo "Stopping local testnet..."
	@./scripts/testnet.sh stop

## testnet-reset: Reset local testnet
testnet-reset:
	@echo "Resetting local testnet..."
	@./scripts/testnet.sh reset

## keys-add: Add a new key
keys-add:
	@$(BUILD_DIR)/$(BINARY_NAME) keys add $(name)

## keys-list: List all keys
keys-list:
	@$(BUILD_DIR)/$(BINARY_NAME) keys list

## status: Show node status
status:
	@$(BUILD_DIR)/$(BINARY_NAME) status

## version: Show version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

# Module-specific targets

## seal-query: Query seal module
seal-query:
	@$(BUILD_DIR)/$(BINARY_NAME) query seal $(args)

## pouw-query: Query pouw module
pouw-query:
	@$(BUILD_DIR)/$(BINARY_NAME) query pouw $(args)

## verify-query: Query verify module
verify-query:
	@$(BUILD_DIR)/$(BINARY_NAME) query verify $(args)

## submit-job: Submit a compute job
submit-job:
	@echo "Submitting compute job..."
	@$(BUILD_DIR)/$(BINARY_NAME) tx pouw submit-job $(args)

## register-model: Register an AI model
register-model:
	@echo "Registering AI model..."
	@$(BUILD_DIR)/$(BINARY_NAME) tx pouw register-model $(args)

# Development helpers

## mod-tidy: Tidy go modules
mod-tidy:
	@echo "Tidying go modules..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) mod tidy

## mod-download: Download go modules
mod-download:
	@echo "Downloading go modules..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) mod download

## benchmark: Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

## profile: Generate CPU profile
profile:
	@echo "Generating CPU profile..."
	$(GO) test -cpuprofile=cpu.prof -bench=. ./app

## trace: Generate execution trace
trace:
	@echo "Generating execution trace..."
	$(GO) test -trace=trace.out -bench=. ./app

# ============================================================================
# Rust Targets (crates/)
# ============================================================================

## rust-build: Build all Rust crates
rust-build:
	@echo "Building Rust crates..."
	cd crates && cargo build --release --workspace

## rust-test: Run all Rust tests
rust-test:
	@echo "Running Rust tests..."
	cd crates && cargo test --all-features --workspace

## rust-lint: Run Rust linters
rust-lint:
	@echo "Running Rust linters..."
	cd crates && cargo fmt --all -- --check
	cd crates && cargo clippy --all-targets --all-features -- -D warnings

## rust-clean: Clean Rust build artifacts
rust-clean:
	@echo "Cleaning Rust build artifacts..."
	cd crates && cargo clean

# ============================================================================
# Full Stack Targets
# ============================================================================

## build-all: Build both Go and Rust stacks
build-all: build rust-build

## test-all: Test both Go and Rust stacks
test-all: test rust-test

## lint-all: Lint both Go and Rust stacks
lint-all: lint rust-lint

## clean-all: Clean both Go and Rust build artifacts
clean-all: clean rust-clean

# ============================================================================
# Solidity Contracts Targets
# ============================================================================

## contracts-install: Install contract dependencies
contracts-install:
	@echo "Installing contract dependencies..."
	cd contracts && npm ci

## contracts-build: Compile Solidity contracts
contracts-build:
	@echo "Compiling Solidity contracts..."
	cd contracts && npx hardhat compile

## contracts-test: Run contract tests
contracts-test:
	@echo "Running contract tests..."
	cd contracts && npx hardhat test

## contracts-lint: Lint Solidity contracts
contracts-lint:
	@echo "Linting Solidity contracts..."
	cd contracts && npx solhint 'contracts/**/*.sol'

# ============================================================================
# Frontend Targets
# ============================================================================

## frontend-install: Install frontend dependencies
frontend-install:
	@echo "Installing frontend dependencies..."
	cd frontend && npm ci

## frontend-build: Build frontend
frontend-build:
	@echo "Building frontend..."
	cd frontend && npm run build

## frontend-dev: Start frontend dev server
frontend-dev:
	@echo "Starting frontend dev server..."
	cd frontend && npm run dev

# ============================================================================
# SDK Targets
# ============================================================================

## sdk-build: Build all SDKs
sdk-build:
	@echo "Building TypeScript SDK..."
	cd sdk/typescript && npm ci && npm run build

## sdk-test: Test all SDKs
sdk-test:
	@echo "Testing TypeScript SDK..."
	cd sdk/typescript && npm test

# ============================================================================
# Tools Targets
# ============================================================================

## tools-build: Build developer tools
tools-build:
	@echo "Building developer tools..."
	cd tools && npm ci && npm run build 2>/dev/null || true

# ============================================================================
# Full Monorepo Targets
# ============================================================================

## build-monorepo: Build all stacks (Go, Rust, Solidity, SDK, Frontend)
build-monorepo: build rust-build contracts-build sdk-build frontend-build

## test-monorepo: Test all stacks
test-monorepo: test rust-test contracts-test sdk-test

# ============================================================================
# Local Testnet (Docker Compose)
# ============================================================================

## local-testnet-up: Start local testnet (mock or real-node via AETHELRED_LOCAL_TESTNET_PROFILE)
local-testnet-up:
	@bash scripts/devtools-local-testnet.sh up

## local-testnet-down: Stop local testnet
local-testnet-down:
	@bash scripts/devtools-local-testnet.sh down

## local-testnet-status: Show local testnet service status
local-testnet-status:
	@bash scripts/devtools-local-testnet.sh status

## local-testnet-logs: Stream local testnet logs
local-testnet-logs:
	@bash scripts/devtools-local-testnet.sh logs

## local-testnet-doctor: Health-check all local testnet services
local-testnet-doctor:
	@bash scripts/devtools-local-testnet.sh doctor

# ============================================================================
# Devnet Launch Controls
# ============================================================================

## devnet-validate: Run devnet genesis, compose, and documentation readiness checks
devnet-validate:
	@bash scripts/devnet-control.sh validate

## devnet-release-genesis-check: Reject placeholder genesis fields before hosted devnet release
devnet-release-genesis-check:
	@python3 ./scripts/validate-devnet-genesis.py --release tools/devnet/genesis.json

## devnet-up: Start the full local devnet cluster
devnet-up:
	@bash scripts/devnet-control.sh up

## devnet-clean-start: Rebuild and start the full local devnet cluster from clean state
devnet-clean-start:
	@bash scripts/devnet-control.sh clean-start

## devnet-down: Stop the full local devnet cluster
devnet-down:
	@bash scripts/devnet-control.sh down

## devnet-status: Show full local devnet container status
devnet-status:
	@bash scripts/devnet-control.sh status

## devnet-logs: Stream full local devnet logs
devnet-logs:
	@bash scripts/devnet-control.sh logs

## devnet-doctor: Run full local devnet runtime health checks
devnet-doctor:
	@bash scripts/devnet-control.sh doctor

## devnet-endpoints: Print full local devnet service endpoints
devnet-endpoints:
	@bash scripts/devnet-control.sh endpoints
