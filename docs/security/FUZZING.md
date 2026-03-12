# Fuzzing Infrastructure

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-02-28
**Owner**: Security Engineering

---

## 1. Overview

This document defines the fuzzing strategy for the Aethelred Protocol. Fuzzing
automatically generates random inputs to discover crashes, panics, assertion
failures, and logic bugs that manual testing misses.

---

## 2. Fuzzing Targets

### 2.1 Priority 1 - Security-Critical (Must Fuzz Before Testnet)

| Target | Language | Tool | What to Fuzz |
|--------|----------|------|--------------|
| VRF prove/verify | Rust | `cargo-fuzz` / `libFuzzer` | Arbitrary messages, key derivation, proof parsing |
| Bridge event processor | Rust | `cargo-fuzz` | Deposit/burn validation, reorg handling, event parsing |
| Token transfers | Solidity | Foundry `forge fuzz` | Amounts, addresses, blacklist combinations |
| Vesting computation | Solidity | Foundry `forge fuzz` | Cliff/TGE boundaries, extreme durations, overflow inputs |
| Bridge withdrawal | Solidity | Foundry `forge fuzz` | Replay, rate limits, signature validation |

### 2.2 Priority 2 - Important (Must Fuzz Before Mainnet)

| Target | Language | Tool | What to Fuzz |
|--------|----------|------|--------------|
| Consensus vote extensions | Go | `go-fuzz` / `testing/fuzz` | Malformed JSON, extreme values, partial messages |
| TEE attestation parsing | Go | `go-fuzz` | Invalid quotes, wrong platforms, expired timestamps |
| WASM VM execution | Rust | `cargo-fuzz` | Arbitrary WASM bytecode, gas limits, memory bounds |
| SDK input validation | TypeScript | `fast-check` | API inputs, transaction construction |

### 2.3 Priority 3 - Defense-in-Depth

| Target | Language | Tool | What to Fuzz |
|--------|----------|------|--------------|
| Serialization (bincode/JSON) | Rust/Go | `cargo-fuzz` / `go-fuzz` | Round-trip encoding, malformed bytes |
| P2P message handling | Go | `go-fuzz` | Gossip messages, peer discovery |
| Key derivation | Rust | `cargo-fuzz` | Edge-case seeds, epoch derivation chains |

---

## 3. Rust Fuzzing Setup (`cargo-fuzz`)

### 3.1 Directory Structure

```
crates/consensus/fuzz/
├── Cargo.toml
├── fuzz_targets/
│   ├── fuzz_vrf_prove.rs
│   ├── fuzz_vrf_verify.rs
│   ├── fuzz_vrf_proof_parsing.rs
│   └── fuzz_epoch_derivation.rs
└── corpus/
    ├── fuzz_vrf_prove/
    └── fuzz_vrf_verify/
```

### 3.2 Example Fuzz Target: VRF Prove

```rust
// crates/consensus/fuzz/fuzz_targets/fuzz_vrf_prove.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use aethelred_consensus::vrf::{VrfEngine, VrfKeys};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);

    // Skip zero seed (invalid key)
    if seed == [0u8; 32] {
        return;
    }

    let keys = match VrfKeys::from_seed(&seed) {
        Ok(k) => k,
        Err(_) => return,
    };

    let engine = VrfEngine::new();
    let input = &data[32..];

    // Must not panic
    if let Ok((proof, output)) = engine.prove(&keys, input) {
        // Verify must succeed for valid proofs
        let verified = engine.verify(keys.public_key(), input, &proof);
        assert!(verified.is_ok(), "Valid proof failed verification");
        assert_eq!(verified.unwrap(), output, "Output mismatch");
    }
});
```

### 3.3 Example Fuzz Target: VRF Proof Parsing

```rust
// crates/consensus/fuzz/fuzz_targets/fuzz_vrf_proof_parsing.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use aethelred_consensus::vrf::VrfProof;

fuzz_target!(|data: &[u8]| {
    // Must not panic on arbitrary bytes
    match VrfProof::from_bytes(data) {
        Ok(proof) => {
            // Round-trip must preserve data
            let bytes = proof.to_bytes();
            let restored = VrfProof::from_bytes(&bytes).unwrap();
            assert_eq!(proof.gamma, restored.gamma);
            assert_eq!(proof.c, restored.c);
            assert_eq!(proof.s, restored.s);
        }
        Err(_) => {
            // Expected for invalid inputs
        }
    }
});
```

### 3.4 Running Rust Fuzz Targets

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a specific target (runs until stopped or crash found)
cd crates/consensus
cargo fuzz run fuzz_vrf_prove -- -max_total_time=3600  # 1 hour

# Run with sanitizers
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run fuzz_vrf_prove

# Run with coverage guidance
cargo fuzz coverage fuzz_vrf_prove
```

---

## 4. Solidity Fuzzing (Foundry)

### 4.1 Invariant Tests

```solidity
// test/invariants/TokenInvariant.t.sol
contract TokenInvariantTest is Test {
    AethelredToken token;
    Handler handler;

    function setUp() public {
        token = new AethelredToken(...);
        handler = new Handler(token);
        targetContract(address(handler));
    }

    /// @dev Total supply must never change
    function invariant_totalSupplyConstant() public view {
        assertEq(token.totalSupply(), 10_000_000_000 * 1e18);
    }

    /// @dev Blacklisted addresses must have zero allowances
    function invariant_blacklistedNoAllowance() public view {
        for (uint i = 0; i < handler.blacklistedCount(); i++) {
            address a = handler.blacklistedAt(i);
            // Can't approve from blacklisted
            assertEq(token.allowance(a, address(handler)), 0);
        }
    }
}
```

### 4.2 Fuzz Tests

```solidity
// test/fuzz/VestingFuzz.t.sol
contract VestingFuzzTest is Test {
    AethelredVesting vesting;

    /// @dev Vested amount must be monotonically non-decreasing
    function testFuzz_vestedMonotonicity(
        uint256 totalAmount,
        uint64 start,
        uint64 cliff,
        uint64 duration,
        uint64 t1,
        uint64 t2
    ) public {
        totalAmount = bound(totalAmount, 1, 10_000_000_000e18);
        duration = uint64(bound(duration, 1 days, 10 * 365 days));
        cliff = uint64(bound(cliff, 0, duration));
        start = uint64(bound(start, 1, type(uint64).max - duration));
        t1 = uint64(bound(t1, start, start + duration));
        t2 = uint64(bound(t2, t1, start + duration));

        uint256 v1 = vesting.computeVestedAt(totalAmount, start, cliff, duration, t1);
        uint256 v2 = vesting.computeVestedAt(totalAmount, start, cliff, duration, t2);

        assertGe(v2, v1, "Vesting must be monotonic");
        assertLe(v2, totalAmount, "Cannot vest more than total");
    }

    /// @dev Bridge rate limit must never exceed maximum
    function testFuzz_rateLimitEnforced(
        uint256[] calldata amounts
    ) public {
        // ... fuzz deposit amounts and verify rate limit holds
    }
}
```

### 4.3 Running Solidity Fuzz Tests

```bash
# Run all fuzz tests (default 256 runs)
forge test --match-test testFuzz

# Run with more iterations
forge test --match-test testFuzz --fuzz-runs 100000

# Run invariant tests
forge test --match-test invariant --fuzz-runs 10000

# Run with verbose output for debugging
forge test --match-test testFuzz -vvvv
```

---

## 5. Go Fuzzing (`testing/fuzz`)

### 5.1 Vote Extension Parsing

```go
// x/pouw/keeper/consensus_fuzz_test.go
func FuzzVoteExtensionParsing(f *testing.F) {
    // Seed corpus with valid vote extension
    validVE := `{"version":1,"height":100,"timestamp":"2026-01-01T00:00:00Z",...}`
    f.Add([]byte(validVE))

    f.Fuzz(func(t *testing.T, data []byte) {
        var ve VoteExtensionWire
        err := json.Unmarshal(data, &ve)
        if err != nil {
            return // Expected for invalid JSON
        }
        // Validation must not panic
        _ = validateVoteExtension(&ve)
    })
}
```

### 5.2 TEE Attestation Validation

```go
// x/verify/keeper/attestation_fuzz_test.go
func FuzzTEEAttestationValidation(f *testing.F) {
    f.Add([]byte(`{"platform":"aws-nitro","quote":"AAAA...","measurement":"BBBB..."}`))

    f.Fuzz(func(t *testing.T, data []byte) {
        var attestation TEEAttestationWire
        err := json.Unmarshal(data, &attestation)
        if err != nil {
            return
        }
        // Must not panic on any input
        _ = validateTEEAttestation(&attestation)
    })
}
```

### 5.3 Running Go Fuzz Tests

```bash
# Run a specific fuzz test for 5 minutes
go test -fuzz=FuzzVoteExtensionParsing -fuzztime=5m ./x/pouw/keeper/

# Run with race detector
go test -race -fuzz=FuzzTEEAttestationValidation -fuzztime=5m ./x/verify/keeper/
```

---

## 6. Continuous Fuzzing (CI)

### 6.1 CI Pipeline Configuration

```yaml
# .github/workflows/fuzzing.yml
name: Continuous Fuzzing
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
  push:
    branches: [main]

jobs:
  rust-fuzz:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - fuzz_vrf_prove
          - fuzz_vrf_verify
          - fuzz_vrf_proof_parsing
          - fuzz_bridge_event_processing
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: |
          cd crates/consensus
          cargo fuzz run ${{ matrix.target }} -- \
            -max_total_time=1800 \
            -print_final_stats=1
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: crash-${{ matrix.target }}
          path: crates/consensus/fuzz/artifacts/

  solidity-fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: foundry-rs/foundry-toolchain@v1
      - run: |
          cd contracts
          forge test --match-test "testFuzz|invariant" \
            --fuzz-runs 50000

  go-fuzz:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - FuzzVoteExtensionParsing
          - FuzzTEEAttestationValidation
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: |
          go test -fuzz=${{ matrix.target }} \
            -fuzztime=30m \
            ./x/pouw/keeper/ ./x/verify/keeper/
```

### 6.2 OSS-Fuzz Integration (Planned)

For sustained long-term fuzzing, integrate with Google's OSS-Fuzz:

```yaml
# project.yaml (for OSS-Fuzz submission)
homepage: "https://aethelred.io"
language: rust
main_repo: "https://github.com/aethelred/aethelred-node"
fuzzing_engines:
  - libfuzzer
  - afl
  - hongfuzz
sanitizers:
  - address
  - memory
  - undefined
```

---

## 7. Crash Triage Process

1. **Detection**: Fuzzer finds a crash and saves the input to `artifacts/`
2. **Reproduce**: Developer replays the crash locally: `cargo fuzz run <target> artifacts/<crash-file>`
3. **Classify**: Determine severity (panic/assert = Medium, memory safety = Critical)
4. **Fix**: Patch the root cause, add regression test
5. **Verify**: Confirm the crash input no longer triggers, add to seed corpus
6. **Release**: Follow standard security fix process (see incident response)

---

## 8. Coverage Goals

| Target | Lines Covered by Fuzzing | Target |
|--------|--------------------------|--------|
| VRF module | Prove, verify, key derivation, parsing | >80% |
| Bridge processor | All event handlers, validation | >70% |
| Token contract | Transfer, approve, blacklist, burn | >85% |
| Vesting contract | Compute vested, release, cliff/TGE | >85% |
| Vote extension parsing | All validation paths | >90% |
