# Code Quality & Test Coverage Standards

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-02-28
**Owner**: Engineering / Security

---

## 1. Overview

This document defines the code quality standards, test coverage requirements,
and CI enforcement mechanisms for the Aethelred Protocol. All code merged to
`main` must meet these standards.

---

## 2. Test Coverage Targets

### 2.1 Coverage Requirements by Layer

| Layer | Language | Minimum Coverage | Critical Path Coverage | Tool |
|-------|----------|------------------|------------------------|------|
| Consensus modules | Go | 90% | 100% | `go test -cover` |
| State machine (`x/`) | Go | 90% | 100% | `go test -cover` |
| ABCI handlers | Go | 85% | 100% | `go test -cover` |
| Smart contracts | Solidity | 95% | 100% | `forge coverage` |
| Bridge relayer | Rust | 90% | 100% | `cargo tarpaulin` |
| Consensus engine | Rust | 90% | 100% | `cargo tarpaulin` |
| VM runtime | Rust | 85% | 95% | `cargo tarpaulin` |
| Core crypto | Rust | 95% | 100% | `cargo tarpaulin` |
| SDK (TypeScript) | TS | 80% | 90% | `jest --coverage` |
| SDK (Python) | Python | 80% | 90% | `pytest --cov` |

### 2.2 Definition of "Critical Path"

A function is on the critical path if it:
- Handles funds (transfer, mint, burn, bridge, vesting)
- Performs cryptographic operations (sign, verify, hash, VRF)
- Enforces access control (role checks, blacklist, governance)
- Validates consensus state transitions
- Parses untrusted input (RPC, P2P, events)

Critical path functions require **100% branch coverage** (not just line coverage).

---

## 3. Test Categories

### 3.1 Required Test Types

| Type | Description | When Required |
|------|-------------|---------------|
| **Unit tests** | Test individual functions in isolation | Every function |
| **Integration tests** | Test module interactions | Every cross-module flow |
| **Property tests** | Random input generation, invariant checking | Security-critical paths |
| **Fuzz tests** | Crash/panic discovery via random bytes | Parsing, crypto, validation |
| **Negative tests** | Verify that invalid inputs are rejected | Every validation function |
| **Boundary tests** | Test edge cases (zero, max, overflow) | Arithmetic, limits |
| **Fork tests** | Test against real chain state | Contract upgrades |
| **Benchmark tests** | Performance regression detection | Critical hot paths |

### 3.2 Test Naming Conventions

```go
// Go: TestUnit_FunctionName_Scenario
func TestUnit_VestedAmount_CliffNotReached(t *testing.T) { ... }
func TestUnit_VestedAmount_FullyVested(t *testing.T) { ... }
func TestIntegration_BridgeDeposit_EndToEnd(t *testing.T) { ... }
func TestNegative_Transfer_BlacklistedSender(t *testing.T) { ... }
func FuzzVoteExtensionParsing(f *testing.F) { ... }
```

```rust
// Rust: test_unit_function_name_scenario
#[test]
fn test_unit_vrf_prove_deterministic() { ... }
#[test]
fn test_negative_vrf_invalid_key() { ... }
#[test]
fn test_boundary_vrf_zero_seed() { ... }
```

```solidity
// Solidity: test_Unit_FunctionName_Scenario / testFuzz_FunctionName
function test_Unit_Transfer_BlacklistedReverts() public { ... }
function testFuzz_VestedAmount_Monotonic(uint256 t1, uint256 t2) public { ... }
function invariant_TotalSupplyConstant() public { ... }
```

---

## 4. Static Analysis

### 4.1 Required Linters

| Language | Tool | Configuration | Enforcement |
|----------|------|---------------|-------------|
| Go | `golangci-lint` | `.golangci.yml` (strict) | CI blocking |
| Rust | `clippy` | `#![deny(clippy::all)]` | CI blocking |
| Solidity | `slither` | `slither.config.json` | CI blocking |
| Solidity | `solhint` | `.solhint.json` | CI blocking |
| TypeScript | `eslint` + `@typescript-eslint` | `.eslintrc.js` | CI blocking |

### 4.2 Clippy Configuration (Rust)

```toml
# clippy.toml
cognitive-complexity-threshold = 25
too-many-arguments-threshold = 7
type-complexity-threshold = 250

# In lib.rs / main.rs:
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,        // No .unwrap() in production code
    clippy::expect_used,        // No .expect() in production code
    clippy::panic,              // No panic!() in production code
    clippy::integer_arithmetic, // Explicit overflow handling required
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
)]
```

### 4.3 Slither Detectors (Solidity)

Run all detectors, with these as CI-blocking:

```bash
slither contracts/ \
    --detect reentrancy-eth,reentrancy-no-eth,\
             uninitialized-state,unprotected-upgrade,\
             arbitrary-send-erc20,suicidal,\
             controlled-delegatecall,tx-origin \
    --fail-on high
```

---

## 5. Code Review Standards

### 5.1 Review Requirements

| Change Type | Reviewers Required | Security Review |
|-------------|-------------------|-----------------|
| Critical path code | 2 engineers + 1 security | Required |
| Non-critical code | 1 engineer | Recommended |
| Documentation only | 1 engineer | Not required |
| Dependency updates | 1 engineer + 1 security | Required |
| Config changes | 1 engineer + 1 SRE | Not required |

### 5.2 Security Review Checklist

Every PR touching security-critical code must address:

- [ ] **Input validation**: All external inputs validated and bounded
- [ ] **Overflow protection**: No unchecked arithmetic on user-controlled values
- [ ] **Access control**: Role/permission checks present and correct
- [ ] **Reentrancy**: No external calls before state updates (CEI pattern)
- [ ] **Error handling**: No panics/unwraps; errors propagated correctly
- [ ] **Logging**: No sensitive data in logs; appropriate log levels
- [ ] **Tests**: Positive, negative, and boundary tests present
- [ ] **Documentation**: Function-level docs for public APIs

---

## 6. CI Pipeline

### 6.1 Required CI Checks (All Must Pass)

```yaml
# .github/workflows/ci.yml
jobs:
  go-tests:
    steps:
      - run: go test -race -coverprofile=cover.out ./...
      - run: |
          COVERAGE=$(go tool cover -func=cover.out | grep total | awk '{print $3}')
          if (( $(echo "$COVERAGE < 90" | bc -l) )); then
            echo "Coverage $COVERAGE% below 90% threshold"
            exit 1
          fi

  rust-tests:
    steps:
      - run: cargo test --all-features
      - run: cargo clippy --all-features -- -D warnings
      - run: cargo tarpaulin --all-features --out xml
      # Enforce 90% coverage

  solidity-tests:
    steps:
      - run: forge test --gas-report
      - run: forge coverage
      # Enforce 95% coverage
      - run: slither contracts/ --fail-on high

  security-audit:
    steps:
      - run: cargo audit  # Rust dependency vulnerabilities
      - run: npm audit     # Node dependency vulnerabilities
      - run: govulncheck ./...  # Go dependency vulnerabilities
```

### 6.2 Coverage Enforcement

Coverage gates are enforced in CI. PRs that decrease coverage below
thresholds are automatically blocked.

```yaml
# codecov.yml
coverage:
  status:
    project:
      default:
        target: 90%
        threshold: 1%
    patch:
      default:
        target: 95%  # New code must be 95%+ covered
```

---

## 7. Dependency Management

### 7.1 Vendoring Policy

| Language | Strategy | Verification |
|----------|----------|--------------|
| Rust | Full vendor in `vendor/` | `cargo vendor --locked` |
| Go | `go.sum` committed | `go mod verify` in CI |
| Solidity | OpenZeppelin via npm | `package-lock.json` committed |

### 7.2 Dependency Audit Schedule

| Frequency | Action | Tool |
|-----------|--------|------|
| Every PR | Automated vulnerability scan | `cargo audit`, `npm audit`, `govulncheck` |
| Weekly | Dependency update review | Dependabot / Renovate |
| Monthly | Manual audit of critical deps | Security team review |
| Quarterly | Full dependency tree audit | External security review |

### 7.3 Approved Cryptographic Dependencies

Only these cryptographic libraries are approved for production use:

| Library | Version | Purpose | Audit Status |
|---------|---------|---------|--------------|
| `k256` | 0.13.x | secp256k1 ECDSA, VRF | RustCrypto audited |
| `p256` | 0.13.x | NIST P-256 | RustCrypto audited |
| `sha2` | 0.10.x | SHA-256/SHA-512 | RustCrypto audited |
| `aes-gcm` | 0.10.x | AES-256-GCM encryption | RustCrypto audited |
| `ed25519-dalek` | 2.x | Ed25519 signatures | Audited |
| `pqcrypto-dilithium` | 0.5.x | ML-DSA (Dilithium3) | NIST PQC standard |
| `zeroize` | 1.x | Secret key cleanup | RustCrypto audited |
| `subtle` | 2.x | Constant-time operations | RustCrypto audited |
| OpenZeppelin | 5.x | Solidity security | Multiple audits |

Adding new cryptographic dependencies requires security team approval.

---

## 8. Performance Benchmarks

### 8.1 Required Benchmarks

| Operation | Target Latency | Measurement |
|-----------|----------------|-------------|
| VRF prove | < 5ms | `criterion` benchmark |
| VRF verify | < 3ms | `criterion` benchmark |
| Block validation | < 500ms | Integration benchmark |
| Token transfer (EVM) | < 50k gas | Foundry gas report |
| Bridge withdrawal (EVM) | < 200k gas | Foundry gas report |
| SHA-256 hash (32 bytes) | < 1us | `criterion` benchmark |

### 8.2 Regression Detection

Performance benchmarks run in CI. Any regression > 10% triggers a warning;
any regression > 25% blocks the PR.

```bash
# Run benchmarks and compare against baseline
cargo bench --bench consensus_benchmarks -- --save-baseline pr-$PR_NUMBER
cargo bench --bench consensus_benchmarks -- --baseline main --output-format criterion
```
