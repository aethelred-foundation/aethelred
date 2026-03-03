# Aethelred Full Audit Report v2 - Remediation Matrix (36 Findings)

Source report: `Aethelred_Full_Audit_Report_v2.pdf` (36 findings: 6 critical, 12 high, 10 medium, 8 low/info)

Status legend:
- `Remediated` = code/config changed to eliminate or fail-close the identified risk
- `Remediated (hard fail)` = placeholder/insecure behavior removed; runtime now requires explicit production integration
- `Remediated + guardrail` = fix plus CI/config validation added

## Critical (C-01 to C-06)

| ID | Status | Remediation |
|---|---|---|
| C-01 | Remediated | Bridge deposit lifecycle finalized on-chain (`finalizeDeposit`) and `cancelDeposit` guarded by finalization/cancellation state in `contracts/contracts/AethelredBridge.sol`. |
| C-02 | Remediated | Contract-admin/multisig enforcement added across initializers; upgrader separated behind timelock pattern (`initializeWithTimelock`) in `contracts/contracts/AethelredBridge.sol`, `contracts/contracts/AethelredToken.sol`, `contracts/contracts/AethelredVesting.sol`, `contracts/contracts/InstitutionalStablecoinBridge.sol`, `contracts/contracts/SovereignGovernanceTimelock.sol`. |
| C-03 | Remediated | `AllowSimulated` production bypass hardened via production-mode checks/build-tag controls and one-way governance gate in `aethelred-cosmos-node/x/pouw/keeper/consensus.go`, `aethelred-cosmos-node/x/pouw/keeper/consensus_testing_override_nonprod.go`, `aethelred-cosmos-node/x/pouw/keeper/scheduler.go`. |
| C-04 | Remediated | Vesting cliff/linear math corrected (elapsed-from-cliff) and explicit schedule activation added in `contracts/contracts/AethelredVesting.sol`. |
| C-05 | Remediated (hard fail) | TypeScript PQC `verify()` placeholder acceptance removed; PQC operations now fail closed until a real backend is injected in `sdk/typescript/src/crypto/pqc.ts`. |
| C-06 | Remediated + guardrail | Split integrations compose into production-safe base + dev-only compose; removed simulated TEE/prover defaults from base and added CI compose security guard in `aethelred-integrations-repo/docker/docker-compose.yml`, `aethelred-integrations-repo/docker/docker-compose.dev.yml`, `scripts/validate-compose-security.sh`, `.github/workflows/audit-config-guards.yml`. |

## High (H-01 to H-12)

| ID | Status | Remediation |
|---|---|---|
| H-01 | Remediated | `bridgeBurn()` enforces ERC-20 allowance via `_spendAllowance` in `contracts/contracts/AethelredToken.sol`. |
| H-02 | Remediated | Deposit IDs use collision-safe encoding in `contracts/contracts/AethelredBridge.sol`. |
| H-03 | Remediated | Relayer count/threshold synchronization added on role changes in `contracts/contracts/AethelredBridge.sol`. |
| H-04 | Remediated | ISB mint ceiling TOCTOU fixed via atomic usage reservation/check before mint path in `contracts/contracts/InstitutionalStablecoinBridge.sol`. |
| H-05 | Remediated | Emergency withdrawal path blocked by pause-state constraints in `contracts/contracts/AethelredBridge.sol`. |
| H-06 | Remediated | Timelock self-grants removed / constructor self-privileging path closed in `contracts/contracts/SovereignGovernanceTimelock.sol`. |
| H-07 | Remediated | `setCategoryCap()` now enforces `cap >= allocated` invariant in `contracts/contracts/AethelredVesting.sol`. |
| H-08 | Remediated (hard fail + dev-stub isolation) | Rust pillar placeholders hardened with production compile guards, deterministic non-empty dev placeholders, priority scheduling, and stronger randomness IDs in `core/src/pillars/`. |
| H-09 | Remediated | PoR checks run inline on mint path and Chainlink Automation-compatible external keeper added in `contracts/contracts/InstitutionalStablecoinBridge.sol` and `contracts/contracts/InstitutionalReserveAutomationKeeper.sol`. |
| H-10 | Remediated (hard fail) | TypeScript PQC `sign()` no longer produces hash-padded fake signatures; it now requires an injected production PQC provider in `sdk/typescript/src/crypto/pqc.ts`. |
| H-11 | Remediated (hard fail) | TypeScript SEV/Nitro verification no longer returns placeholder `true`; backend parser/verifier callbacks are required for signature verification in `sdk/typescript/src/crypto/tee.ts`. |
| H-12 | Remediated + guardrail | Hardcoded Grafana `admin` password removed from integrations compose and devnet compose; production compose uses Docker secret file and internal observability network. CI guard rejects default password in non-dev compose. Files: `aethelred-integrations-repo/docker/docker-compose.yml`, `aethelred-integrations-repo/docker/docker-compose.dev.yml`, `aethelred-developer-tools/devnet/docker-compose.yml`, `scripts/validate-compose-security.sh`. |

## Medium (M-01 to M-10)

| ID | Status | Remediation |
|---|---|---|
| M-01 | Remediated | EIP-712 domain-separated typed signatures implemented in `contracts/contracts/InstitutionalStablecoinBridge.sol` with wrong-domain regression coverage in `contracts/test/institutional.stablecoin.integration.test.ts`. |
| M-02 | Remediated | Unbounded outflow mappings replaced with bounded/ring-buffered storage in `contracts/contracts/InstitutionalStablecoinBridge.sol` with 48h/14d slot-wrap regressions in `contracts/test/institutional.stablecoin.integration.test.ts`. |
| M-03 | Remediated | `recoverTokens()` surplus handling made safe/saturating in `contracts/contracts/AethelredVesting.sol` with regression coverage in `contracts/test/medium.findings.regression.test.ts`. |
| M-04 | Remediated | Validator zone-cap TOCTOU mitigated by post-write invariant recheck/rollback in `aethelred-cosmos-node/x/validator/keeper/keeper.go` with rollback regression test in `aethelred-cosmos-node/x/validator/keeper/keeper_additional_test.go`. |
| M-05 | Remediated + guardrail | PoUW validator selection hardened with deterministic entropy salt/randomized tie-break behavior in `aethelred-cosmos-node/x/pouw/keeper/staking.go`; static guard added in `scripts/validate-pouw-medium-guards.sh` (workspace `x/pouw` tests blocked by missing internal deps). |
| M-06 | Remediated | `adminBurn()` now requires allowance/consent path (removing unilateral instant burns) in `contracts/contracts/AethelredToken.sol` with regression coverage in `contracts/test/medium.findings.regression.test.ts`. |
| M-07 | Remediated + runnable evidence path | TEE quote-type detection hardened in `services/tee-worker/nitro-sdk/src/attestation/engine.rs`; regressions are runnable via `--features attestation-evidence` while broader `full-sdk` stabilization continues. |
| M-08 | Remediated + guardrail | Testing threshold override moved out of production build into non-production file in `aethelred-cosmos-node/x/pouw/keeper/consensus_testing_override_nonprod.go`, with build-tag/placement guard in `scripts/validate-pouw-medium-guards.sh`. |
| M-09 | Remediated + guardrail | Devnet unbonding period raised to 3 days (259200s) and validator script added to enforce floor in `aethelred-developer-tools/devnet/genesis.json`, `scripts/validate-devnet-genesis.py`, `.github/workflows/audit-config-guards.yml`. |
| M-10 | Remediated + guardrail | Devnet `minAttestationsForSeal` and SLA default attestation floor raised to match validator count (3/3 for current devnet) with validator script enforcement in `aethelred-developer-tools/devnet/genesis.json` and `scripts/validate-devnet-genesis.py`. |

## Low / Informational (L-01 to L-08)

| ID | Status | Remediation |
|---|---|---|
| L-01 | Remediated (critical path) | Token burn accounting path moved to deterministic integer fixed-point math in `core/src/pillars/quadratic_burn.rs`, with source-level regressions added for fixed-point burn calculation and non-finite input handling (workspace crate wiring still absent for execution). |
| L-02 | Remediated + guardrail | Upgrade storage gaps present in bridge contracts (`AethelredBridge` and `InstitutionalStablecoinBridge`) in `contracts/contracts/AethelredBridge.sol` and `contracts/contracts/InstitutionalStablecoinBridge.sol`, enforced by `scripts/validate-low-findings-guards.sh`. |
| L-03 | Remediated + guardrail + runnable evidence path | EPID-specific leak removed in favor of generic unsupported format error in `services/tee-worker/nitro-sdk/src/attestation/engine.rs`; regression is runnable via `--features attestation-evidence` and generic-string guard is enforced in `scripts/validate-low-findings-guards.sh`. |
| L-04 | Remediated (with source-level regression) | `cosine_similarity()` zero/invalid denominator guard added in `core/src/pillars/vector_vault.rs`, with zero-vector/NaN regression added in the same file (workspace crate wiring still absent for execution). |
| L-05 | Remediated + guardrail | `.DS_Store` ignored across repos (`contracts`, `aethelred-cosmos-node`, `services/tee-worker/nitro-sdk`) and additional integrations docker secrets ignore added in `aethelred-integrations-repo/docker/.gitignore`; ignore/tracked-file checks enforced by `scripts/validate-low-findings-guards.sh`. |
| L-06 | Remediated + guardrail | Rust `target/` artifacts ignored in `services/tee-worker/nitro-sdk/.gitignore`, with tracked-artifact checks enforced by `scripts/validate-low-findings-guards.sh`. |
| L-07 | Remediated (hard fail) | Placeholder Nitro root certificate string removed from TypeScript SDK; Nitro verification now requires explicitly configured trusted roots/backend verifier in `sdk/typescript/src/crypto/tee.ts`, with fail-closed regressions in `sdk/typescript/src/crypto/tee.test.ts` and static guard in `scripts/validate-low-findings-guards.sh`. |
| L-08 | Remediated | TypeScript SDK client supports API-key auth header injection (`X-API-Key`) and regression test added in `sdk/typescript/src/core/client.ts` and `sdk/typescript/src/core/client.test.ts`, with header-presence guard in `scripts/validate-low-findings-guards.sh`. |

## Regression Tests / Guards Added for v2 Delta

- High findings contract regressions (H-01/H-02/H-03/H-05/H-06/H-07):
  - `contracts/test/high.findings.regression.test.ts`
- TypeScript crypto regressions:
  - `sdk/typescript/src/crypto/pqc.test.ts`
  - `sdk/typescript/src/crypto/tee.test.ts`
- Rust pillar hardening behavior tests (H-08) added in source test modules:
  - `core/src/pillars/secret_mempool.rs`
  - `core/src/pillars/zero_copy_bridge.rs`
  - `core/src/pillars/vector_vault.rs`
- Integrations compose security guard:
  - `scripts/validate-compose-security.sh`
  - `.github/workflows/audit-config-guards.yml`
- Devnet genesis security floor validator:
  - `scripts/validate-devnet-genesis.py`
- Medium findings regressions / guards (M-01..M-10):
  - `contracts/test/medium.findings.regression.test.ts`
  - `contracts/test/institutional.stablecoin.integration.test.ts`
  - `aethelred-cosmos-node/x/validator/keeper/keeper_additional_test.go`
  - `services/tee-worker/nitro-sdk/src/attestation/engine.rs`
  - `scripts/validate-pouw-medium-guards.sh`
- Low findings regressions / guards (L-01..L-08):
  - `core/src/pillars/quadratic_burn.rs`
  - `core/src/pillars/vector_vault.rs`
  - `services/tee-worker/nitro-sdk/src/attestation/engine.rs`
  - `sdk/typescript/src/crypto/tee.test.ts`
  - `sdk/typescript/src/core/client.test.ts`
  - `scripts/validate-low-findings-guards.sh`
