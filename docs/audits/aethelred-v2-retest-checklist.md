# Aethelred v2 Audit Re-Test Checklist (Compact)

Purpose: give auditors a deterministic, low-friction retest path for the 36 v2 findings (C/H/M/L), with one bundled command and targeted spot checks.

## 1. One-Command Evidence Bundle

Run from:
- `.`

Command:

```bash
bash ./scripts/run-audit-remediation-evidence-bundle.sh .
```

What it covers:
- Critical contract regressions (`C-01`, `C-02`, `C-04`)
- High contract regressions (`H-01`..`H-07`, `H-09`)
- Medium contract/go/guard regressions (`M-01`..`M-10`)
- Low guardrails (`L-01`..`L-08`)
- TypeScript SDK crypto/client regressions (`C-05`, `H-10`, `H-11`, `L-07`, `L-08`)
- Rust attestation engine regressions for:
  - `M-07` quote-type detection hardening
  - `L-03` generic unsupported-format error (no EPID leak)

Expected final line:
- `Audit remediation evidence bundle completed successfully.`

Latest local run log (this pass):
- `/tmp/aethelred-audit-remediation-evidence-20260223-213400.log`

## 2. Auditor Spot Checks (Recommended)

### Critical

1. `C-01` Bridge deposit finalization blocks cancellation
- Test: `contracts/test/bridge.emergency.test.ts`
- Case: `finalizeDeposit sets finalized flag and prevents later cancellation`

2. `C-04` Vesting cliff/linear math
- Test: `contracts/test/vesting.critical.test.ts`
- Cases:
  - cliff-end vests `0`
  - `activateSchedule()` anchors to `tgeTime`

3. `C-05` TypeScript PQC fail-closed
- Test: `sdk/typescript/src/crypto/pqc.test.ts`

4. `C-06` Compose production/dev split + simulated-mode guard
- Guard script: `scripts/validate-compose-security.sh`

### High

1. Contract regressions (`H-01`, `H-02`, `H-03`, `H-05`, `H-06`, `H-07`)
- Test: `contracts/test/high.findings.regression.test.ts`

2. ISB PoR / circuit breaker / quotas / velocity / sovereign unpause / Iris fast relay (`H-04`, `H-09`)
- Test: `contracts/test/institutional.stablecoin.integration.test.ts`

3. TS TEE fail-closed (`H-11`) and Nitro trusted-root behavior (`L-07`)
- Test: `sdk/typescript/src/crypto/tee.test.ts`

### Medium

1. Contract regressions (`M-01`, `M-02`, `M-03`, `M-06`)
- Tests:
  - `contracts/test/institutional.stablecoin.integration.test.ts`
  - `contracts/test/medium.findings.regression.test.ts`

2. Go validator rollback regression (`M-04`)
- Test:
  - `aethelred-cosmos-node/x/validator/keeper/keeper_additional_test.go`

3. PoUW medium guards (`M-05`, `M-08`) and devnet config guards (`M-09`, `M-10`)
- Scripts:
  - `scripts/validate-pouw-medium-guards.sh`
  - `scripts/validate-devnet-genesis.py`

4. Rust attestation engine (`M-07`) runnable evidence
- Feature-gated evidence mode command:

```bash
cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features attestation-evidence --lib attestation::engine::tests::test_quote_type_detection_uses_intel_header_fields -- --exact
```

### Low / Informational

1. Low findings guardrail bundle (`L-01`, `L-02`, `L-03`, `L-04`, `L-05`, `L-06`, `L-07`, `L-08`)
- Script:
  - `scripts/validate-low-findings-guards.sh`

2. TS `X-API-Key` regression (`L-08`)
- Test:
  - `sdk/typescript/src/core/client.test.ts`

3. Rust `L-03` EPID generic error regression (runnable)
- Command:

```bash
cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features attestation-evidence --lib attestation::engine::tests::test_epid_quotes_return_generic_unsupported_format_error -- --exact
```

## 3. Rust `nitro-sdk` Full-SDK Stabilization Status (Current)

Progress made in this pass:
- Fixed `lib_full.rs` loader strategy (removed `include!` doc-comment failure path) by loading full SDK as a module from `services/tee-worker/nitro-sdk/src/lib.rs`
- Added missing foundational dependencies in `services/tee-worker/nitro-sdk/Cargo.toml` (`thiserror`, `sha2`, `uuid`, `hex`, `base64`, `rand`, `blake3`)
- Added `attestation-evidence` feature path and feature-gated serde derives for attestation evidence execution

Current `full-sdk` check state:
- `cargo check --features full-sdk` still fails, but error count reduced substantially (from ~294 to ~99 in this pass)

Top remaining blocker classes (outside the audit `attestation::engine` scope):
- Missing modules in `sovereign/` (`types`, `access`, `encryption`, `audit`)
- Missing crypto dependencies (`zeroize`, `sha3`, `hkdf`, `argon2`, `pbkdf2`, `aes_gcm`, `chacha20poly1305`, `bincode`, etc.)
- API/visibility mismatches in unrelated modules (`zktensor`, `helix`, `transaction`, `seal`)

## 4. Acceptance Signals for Auditor Re-Test

Accept the remediation retest if all of the following are true:
- Evidence bundle script completes successfully.
- No guard script fails (`compose`, `pouw-medium`, `low-findings`, `devnet-genesis`).
- Rust attestation evidence tests pass under `--features attestation-evidence`.
- Contract regression suite reports no failing tests in the listed files.
- TypeScript SDK security regressions report no failing tests in the listed files.

## 5. Reference Artifacts

- Remediation matrix (all 36 findings):
  - `docs/audits/aethelred-full-audit-report-v2-remediation-matrix.md`
- Evidence bundle runner:
  - `scripts/run-audit-remediation-evidence-bundle.sh`
