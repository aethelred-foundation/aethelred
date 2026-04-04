# Launch Gate Inventory

Effective: 2026-03-25
Owner: Release Engineering
Purpose: Enumerate every gate that must pass before testnet and mainnet launch.

---

## Gate Summary

| Gate ID | Gate Name | Validation Method | Automated | CI Workflow | Owner Squad | Evidence Artifact |
|---------|-----------|-------------------|-----------|-------------|-------------|-------------------|
| G-BUILD | Build gate | `go build ./cmd/aethelredd` succeeds | Yes | `CI` (`.github/workflows/ci.yml`) | Core Protocol | Binary at `./build/aethelredd` |
| G-UNIT | Unit test gate | `make test-unit` passes | Yes | `CI` (`.github/workflows/ci.yml`) | Core Protocol | Test output in CI logs |
| G-INT | Integration test gate | `make test-integration` passes | Yes | `CI` (`.github/workflows/ci.yml`) | Core Protocol | Test output in CI logs |
| G-CONS | Consensus test gate | `make test-consensus` passes | Yes | `CI` (`.github/workflows/ci.yml`) | Core Protocol | Test output in CI logs |
| G-COV | Coverage gate | `make coverage-critical` (>=95% on `x/pouw`, `x/verify`) | Yes | `CI` (`.github/workflows/ci.yml`) | Core Protocol | `coverage.out` report |
| G-AUDIT | Contract audit gate | `make audit-signoff-check` | Semi | `Audit Config Guards` (`.github/workflows/audit-config-guards.yml`) | Security | Signed audit reports in `docs/audits/` |
| G-SDK | SDK version gate | `make sdk-version-check` | Yes | `SDK Release Readiness` (`.github/workflows/sdk-release-readiness.yml`) | SDK | `version-matrix.json` validation output |
| G-SEC | Security scan gate | All scans in `security-scans.yml` pass | Yes | `Security Scans` (`.github/workflows/security-scans.yml`) | Security | Scan reports (gosec, trivy, gitleaks, slither, govulncheck, cargo-audit, npm audit) |
| G-FUZZ | Fuzz gate | No new crashes in nightly fuzz | Yes | `Fuzzing CI` (`.github/workflows/fuzzing-ci.yml`) | Core Protocol | Fuzz corpus artifacts, crash logs |
| G-LOAD | Loadtest gate | All SLOs met in staging | Yes | `Load Testing` (`.github/workflows/loadtest.yml`) | Infrastructure | `loadtest-results/` reports |
| G-E2E | E2E gate | E2E workflow succeeds | Yes | `E2E Chain Tests` (`.github/workflows/e2e-tests.yml`) | Core Protocol | E2E test output in CI logs |
| G-RUST | Rust crates gate | `cargo build` + `cargo test` for all crates | Yes | `Rust Crates CI` (`.github/workflows/rust-crates-ci.yml`) | Core Protocol | Build/test output in CI logs |
| G-CONTRACT | Contracts gate | `forge build` + `forge test` + `npx hardhat test` | Yes | `Contracts CI` (`.github/workflows/contracts-ci.yml`) | Smart Contracts | Test output, coverage report |
| G-DOCKER | Docker gate | Docker images build successfully | Yes | `Docker Build & Push` (`.github/workflows/docker-build.yml`) | Infrastructure | Built image digests |
| G-SANDBOX | Sandbox gate | Sandbox CI passes | Yes | `Infinity Sandbox CI` (`.github/workflows/sandbox-ci.yml`) | Core Protocol | Test output in CI logs |
| G-HELM | Helm gate | Helm chart lint and template tests | Yes | `Helm Charts CI` (`.github/workflows/helm-charts-ci.yml`) | Infrastructure | Lint output in CI logs |
| G-OPENAPI | OpenAPI gate | `make openapi-validate` | Yes | Part of `SDK Release Readiness` | SDK | Validated OpenAPI spec |

---

## Gate Details

### G-BUILD: Build Gate

- **Command**: `make build` (runs `go build ./cmd/aethelredd`)
- **Output**: Binary at `./build/aethelredd`
- **Failure mode**: Compilation error blocks all downstream gates
- **CI workflow**: `CI` -- runs on every push and PR
- **Branch protection**: Part of core CI required check

### G-UNIT: Unit Test Gate

- **Command**: `make test-unit` (runs `go test -short ./...`)
- **Failure mode**: Any test failure blocks merge
- **CI workflow**: `CI`
- **Branch protection**: Part of core CI required check

### G-INT: Integration Test Gate

- **Command**: `make test-integration` (runs `go test -run Integration ./...`)
- **Failure mode**: Any test failure blocks merge
- **CI workflow**: `CI`
- **Branch protection**: Part of core CI required check

### G-CONS: Consensus Test Gate

- **Command**: `make test-consensus`
- **Scope**: Tests in `x/pouw/`, `x/verify/`, `app/` (ABCI++, vote extensions)
- **Failure mode**: Any failure blocks merge
- **CI workflow**: `CI`
- **Branch protection**: Part of core CI required check

### G-COV: Coverage Gate

- **Command**: `make coverage-critical`
- **Threshold**: >=95% line coverage on `x/pouw` and `x/verify` packages
- **Output**: `coverage.out` with per-package breakdown
- **Failure mode**: Coverage below threshold blocks merge
- **CI workflow**: `CI`

### G-AUDIT: Contract Audit Gate

- **Command**: `make audit-signoff-check`
- **Scope**: `contracts/ethereum` and consensus/vote extension code paths
- **Evidence required**: Signed audit reports from external auditors
- **Automation level**: Semi-automated (CI checks for presence of signoff artifacts; actual audit is manual)
- **Current status**: AUD-2026-001 (contracts) and AUD-2026-002 (consensus) in progress
- **CI workflow**: `Audit Config Guards`
- **Tracking**: `docs/audits/STATUS.md`

### G-SDK: SDK Version Gate

- **Command**: `make sdk-version-check`
- **Validates**: SDK versions across TypeScript, Python, Go, Rust match `version-matrix.json`
- **CI workflow**: `SDK Release Readiness`
- **Additional**: `make sdk-release-check` runs version check + OpenAPI validation

### G-SEC: Security Scan Gate

- **Command**: Runs automatically in CI
- **Tools**: gosec, trivy, gitleaks, slither, govulncheck, cargo-audit, npm audit
- **CI workflow**: `Security Scans` (`.github/workflows/security-scans.yml`)
- **Branch protection**: `Security Required Gate`
- **Failure mode**: Any scan finding above configured threshold blocks merge

### G-FUZZ: Fuzz Gate

- **Command**: Runs automatically in CI
- **Go targets**: 4 fuzz targets in `app/vote_extension_fuzz_test.go`
- **Rust targets**: 4 PQC fuzz targets in `crates/core/fuzz/`
- **CI workflow**: `Fuzzing CI` (`.github/workflows/fuzzing-ci.yml`)
- **Branch protection**: `Fuzzing Required Gate`
- **Failure mode**: New crash artifacts block merge

### G-LOAD: Loadtest Gate

- **Command**: `make loadtest` (baseline), `make loadtest-scenarios` (all scenarios)
- **SLOs**: Defined per scenario in load test configuration
- **CI workflow**: `Load Testing` (`.github/workflows/loadtest.yml`)
- **Branch protection**: `Load Test Required Gate`
- **Evidence**: Results stored in `loadtest-results/`

### G-E2E: E2E Gate

- **Command**: Runs automatically in CI
- **Scope**: Full chain E2E including Docker Compose multi-validator topology
- **CI workflow**: `E2E Chain Tests` (`.github/workflows/e2e-tests.yml`)
- **Branch protection**: `E2E Required Gate` (required on `main` and `release/*`)
- **Evidence**: Test logs and Docker container health checks

### G-RUST: Rust Crates Gate

- **Command**: `cargo build --workspace` + `cargo test --workspace` (under `crates/`)
- **CI workflow**: `Rust Crates CI` (`.github/workflows/rust-crates-ci.yml`)
- **Branch protection**: `Rust Required Gate`
- **Additional**: `Rust Coverage & Benchmarks` workflow for coverage tracking

### G-CONTRACT: Contracts Gate

- **Command**: `forge build` + `forge test` + `npx hardhat compile` + `npx hardhat test`
- **CI workflow**: `Contracts CI` (`.github/workflows/contracts-ci.yml`)
- **Branch protection**: `Contracts Required Gate`
- **Additional**: `Contracts Size Gate` checks contract bytecode size limits

### G-DOCKER: Docker Gate

- **Command**: Docker image build
- **CI workflow**: `Docker Build & Push` (`.github/workflows/docker-build.yml`)
- **Branch protection**: `Docker Required Gate`

### G-SANDBOX: Sandbox Gate

- **Command**: Sandbox CI tests
- **CI workflow**: `Infinity Sandbox CI` (`.github/workflows/sandbox-ci.yml`)
- **Branch protection**: `Sandbox Required Gate`

## Branch Protection Mapping

Required checks per branch are defined in `.github/branch-protection/required-checks.json`.

| Branch | Required Gates |
|--------|---------------|
| `main` | Contracts, Rust, Security, Sandbox, Docker, Load Test, Fuzzing, E2E |
| `develop` | Contracts, Rust, Security, Sandbox, Docker, Load Test, Fuzzing |
| `release/*` | Contracts, Rust, Security, Sandbox, Docker, Load Test, Fuzzing, E2E |
| Default (all other) | Contracts, Rust, Security, Sandbox, Docker, Load Test, Fuzzing |

---

## Mainnet Launch Readiness Checklist

All gates below must show `PASS` before mainnet tag is cut:

- [ ] G-BUILD: Binary builds cleanly
- [ ] G-UNIT: All unit tests pass
- [ ] G-INT: All integration tests pass
- [ ] G-CONS: All consensus tests pass
- [ ] G-COV: >=95% coverage on consensus/verify paths
- [ ] G-AUDIT: External audit signoff received (AUD-2026-001, AUD-2026-002)
- [ ] G-SDK: SDK versions consistent across all languages
- [ ] G-SEC: All security scans clean
- [ ] G-FUZZ: No unresolved fuzz crashes
- [ ] G-LOAD: All SLOs met in staging environment
- [ ] G-E2E: E2E chain tests pass
- [ ] G-RUST: All Rust crates build and test
- [ ] G-CONTRACT: All contract tests pass (Foundry + Hardhat)
- [ ] G-DOCKER: Docker images build successfully
- [ ] G-SANDBOX: Sandbox CI passes
- [ ] G-HELM: Helm charts lint clean
- [ ] G-OPENAPI: OpenAPI spec validates
- [ ] Freeze policy compliance verified (see `FREEZE_POLICY.md`)
- [ ] Production-readiness gates G1-G12 from `docs/audits/STATUS.md` all PASS

---

## References

- Freeze policy: [`docs/operations/FREEZE_POLICY.md`](FREEZE_POLICY.md)
- CI/CD gates detail: [`docs/operations/ci-cd-gates.md`](ci-cd-gates.md)
- Branch protection config: [`.github/branch-protection/required-checks.json`](../../.github/branch-protection/required-checks.json)
- Audit status: [`docs/audits/STATUS.md`](../audits/STATUS.md)
- Production-readiness gates: [`docs/audits/STATUS.md` -- Production-Readiness Gate Status](../audits/STATUS.md#production-readiness-gate-status)
