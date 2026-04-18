# Audit Remediation Register

> **Document owner:** Security & Compliance Lead
> **Effective:** 2026-03-25
> **Last reviewed:** 2026-04-17
> **Purpose:** Track the remediation lifecycle for every audit finding across all engagements, categorized by subsystem.

---

## How to Use This Register

1. When a new audit finding is reported, add a row to the appropriate category table below.
2. Update the **Status** column as work progresses through the lifecycle.
3. Link every remediation to a specific PR or commit SHA.
4. Record the verification artifact that proves the fix works.
5. Update the **Date** column when status changes.
6. For Accepted Risk findings, fill in the rationale template at the bottom of this document.

---

## Status Lifecycle

```
Open -> In Progress -> Remediated -> Verified -> CLOSED
                    \-> Accepted Risk (with justification + compensating controls)
                    \-> Disputed (with rationale communicated to auditor)
```

| Status | Definition |
|--------|-----------|
| Open | Finding reported, no remediation started |
| In Progress | Remediation work underway, assigned to owner |
| Remediated | Fix merged; regression test or guard script confirms the fix |
| Verified | Auditor has re-tested and confirmed remediation |
| CLOSED | Fix verified against source code in the main branch |
| Accepted Risk | Risk acknowledged by Security Lead with documented justification and compensating controls |
| Disputed | Finding validity contested; rationale documented and communicated to auditor |
| Remediated Locally | Fix applied in local clone, pending push to public repo |
| Partially Remediated | Some aspects addressed, remaining action items documented |

---

## Category: Smart Contract

**Scope:** `contracts/contracts/`, `contracts/bridges/`, `contracts/test/`
**Audit engagements:** AUD-2026-001, INT-2026-002

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date | Verified |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|----------|
| C-01 | INT-2026-002 | Critical | Smart Contract | Bridge deposit lifecycle not finalized on-chain | CLOSED | Smart Contracts | `contracts/contracts/AethelredBridge.sol` @ `6f2fdd8d` | `contracts/test/bridge.emergency.test.ts`; deposit lifecycle with `_generateDepositId` + nonce confirmed in source | 2026-02-23 | 2026-03-30 |
| C-02 | INT-2026-002 | Critical | Smart Contract | Missing admin/multisig enforcement on initializers | CLOSED | Smart Contracts | Multiple contract files @ `6f2fdd8d` | Contract regression tests; `onlyRole(DEFAULT_ADMIN_ROLE)` guards confirmed in AethelredVesting, AethelredBridge, ISB | 2026-02-23 | 2026-03-30 |
| C-04 | INT-2026-002 | Critical | Smart Contract | Vesting cliff/linear math error | CLOSED | Smart Contracts | `contracts/contracts/AethelredVesting.sol` @ `6f2fdd8d` | `contracts/test/vesting.critical.test.ts`; cliff+linear unlock logic verified in source | 2026-02-23 | 2026-03-30 |
| H-01 | INT-2026-002 | High | Smart Contract | `bridgeBurn()` missing ERC-20 allowance enforcement | CLOSED | Smart Contracts | `contracts/contracts/AethelredToken.sol` @ `6f2fdd8d` | `_spendAllowance(from, msg.sender, amount)` call confirmed in `bridgeBurn()` | 2026-02-23 | 2026-03-30 |
| H-02 | INT-2026-002 | High | Smart Contract | Deposit ID collision risk | CLOSED | Smart Contracts | `contracts/contracts/AethelredBridge.sol` @ `6f2fdd8d` | `_generateDepositId()` uses depositor+recipient+token+amount+nonce; `depositNonce` incremented per deposit | 2026-02-23 | 2026-03-30 |
| H-03 | INT-2026-002 | High | Smart Contract | Relayer count/threshold desync on role changes | CLOSED | Smart Contracts | `contracts/contracts/AethelredBridge.sol` @ `6f2fdd8d` | Bridge contract relayer management verified in source | 2026-02-23 | 2026-03-30 |
| H-04 | INT-2026-002 | High | Smart Contract | ISB mint ceiling TOCTOU | CLOSED | Smart Contracts | `contracts/contracts/InstitutionalStablecoinBridge.sol` @ `6f2fdd8d` | `projectedMinted > cfg.mintCeilingPerEpoch` check inline with mint operation confirmed | 2026-02-23 | 2026-03-30 |
| H-05 | INT-2026-002 | High | Smart Contract | Emergency withdrawal bypasses pause state | CLOSED | Smart Contracts | `contracts/contracts/AethelredBridge.sol` @ `6f2fdd8d` | H-05 guardian multi-sig state added; `emergencyWithdrawalDelay` + timelock enforced | 2026-02-23 | 2026-03-30 |
| H-06 | INT-2026-002 | High | Smart Contract | Timelock self-grant privilege escalation | CLOSED | Smart Contracts | `contracts/contracts/SovereignGovernanceTimelock.sol` @ `6f2fdd8d` | Contract uses OZ `TimelockController` with `MIN_KEY_ROTATION_DELAY = 7 days`; dual-signature consent (Issuer+Foundation) required | 2026-02-23 | 2026-03-30 |
| H-07 | INT-2026-002 | High | Smart Contract | `setCategoryCap()` invariant violation | CLOSED | Smart Contracts | `contracts/contracts/AethelredVesting.sol` @ `6f2fdd8d` | `if (cap < categoryAllocated[category]) revert CategoryCapBelowAllocated()` guard confirmed | 2026-02-23 | 2026-03-30 |
| H-09 | INT-2026-002 | High | Smart Contract | PoR checks not inline on mint path | CLOSED | Smart Contracts | `contracts/contracts/InstitutionalStablecoinBridge.sol` @ `6f2fdd8d` | Chainlink PoR feed integration with `proofOfReserveFeed` config + Automation-compatible `checkUpkeep`/`performUpkeep` confirmed | 2026-02-23 | 2026-03-30 |
| M-01 | INT-2026-002 | Medium | Smart Contract | Missing EIP-712 domain separation | CLOSED | Smart Contracts | `contracts/contracts/InstitutionalStablecoinBridge.sol` @ `6f2fdd8d` | `EIP712_DOMAIN_TYPEHASH`, `EIP712_NAME_HASH`, `EIP712_VERSION_HASH`, `_toTypedDataHash()` confirmed in source | 2026-02-23 | 2026-03-30 |
| M-02 | INT-2026-002 | Medium | Smart Contract | Unbounded outflow mappings | CLOSED | Smart Contracts | `contracts/contracts/InstitutionalStablecoinBridge.sol` @ `6f2fdd8d` | Velocity/quota circuit breakers with `hourlyOutflowBps` and `dailyOutflowBps` confirmed | 2026-02-23 | 2026-03-30 |
| M-03 | INT-2026-002 | Medium | Smart Contract | `recoverTokens()` surplus handling | CLOSED | Smart Contracts | `contracts/contracts/AethelredVesting.sol` @ `6f2fdd8d` | `recoverTokens(address, uint256, address recipient)` with `InvalidBeneficiary` check confirmed | 2026-02-23 | 2026-03-30 |
| M-06 | INT-2026-002 | Medium | Smart Contract | `adminBurn()` unilateral instant burn | CLOSED | Smart Contracts | `contracts/contracts/AethelredToken.sol` @ `6f2fdd8d` | Replaced with `complianceBurn()` requiring `COMPLIANCE_BURN_ROLE` + allowance + `ComplianceSlash` event | 2026-02-23 | 2026-03-30 |
| L-02 | INT-2026-002 | Low | Smart Contract | Missing upgrade storage gaps in bridge | CLOSED | Smart Contracts | Bridge contracts @ `6f2fdd8d` | `uint256[50] private __gap` confirmed in `AethelredBridge.sol` | 2026-02-23 | 2026-03-30 |

---

## Category: Consensus

**Scope:** `app/`, `x/pouw/`, `x/verify/`, `x/validator/`
**Audit engagements:** AUD-2026-002, INT-2026-002

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date | Verified |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|----------|
| C-03 | INT-2026-002 | Critical | Consensus | `AllowSimulated` production bypass not hardened | CLOSED | Core Protocol | `x/pouw/keeper/consensus.go` + `app/allow_simulated_prod.go` @ `6f2fdd8d` | `//go:build !production` on `simulated_build_flag_default.go`; production build init() assertion in `app/allow_simulated_prod.go`; `AllowSimulated=false` error path confirmed | 2026-02-23 | 2026-03-30 |
| M-04 | INT-2026-002 | Medium | Consensus | Validator zone-cap TOCTOU | CLOSED | Core Protocol | `x/validator/keeper/keeper.go` @ `6f2fdd8d` | `enforceValidatorSetConstraints()` atomically reads `countActiveValidatorsByRegion()` and checks `projectedRegion > allowed` before admission | 2026-02-23 | 2026-03-30 |
| M-05 | INT-2026-002 | Medium | Consensus | PoUW validator selection determinism gap | CLOSED | Core Protocol | `x/pouw/keeper/staking.go` @ `6f2fdd8d` | Deterministic seed from `chainID+blockHeight+blockTime` with `selectionTieBreaker()` confirmed | 2026-02-23 | 2026-03-30 |
| M-08 | INT-2026-002 | Medium | Consensus | Test threshold override in production build | CLOSED | Core Protocol | `x/pouw/keeper/consensus_testing_override_nonprod.go` @ `6f2fdd8d` | `//go:build !production` confirmed; `SetConsensusThresholdForTesting` excluded from production binaries | 2026-02-23 | 2026-03-30 |

---

## Category: Bridge (Rust Relayer)

**Scope:** `crates/bridge/`
**Audit engagements:** INT-2026-002

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date | Verified |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|----------|
| _No findings specific to the Rust bridge relayer in current engagements_ | | | | | | | | | | |

---

## Category: Cryptographic

**Scope:** `crates/core/`, `crates/consensus/`, `sdk/typescript/src/crypto/`
**Audit engagements:** CON-2026-001, INT-2026-002

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date | Verified |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|----------|
| RS-01 | CON-2026-001 | Critical | Cryptographic | Non-constant-time hash-to-curve in VRF | CLOSED | Core Protocol | `crates/consensus/src/vrf.rs` (lines 457-496) @ `6f2fdd8d` | RFC 9380 Simplified SWU via `k256::hash2curve::GroupDigest` + `ExpandMsgXmd` confirmed in `hash_to_curve()` | 2026-02-28 | 2026-03-30 |
| C-05 | INT-2026-002 | Critical | Cryptographic | TypeScript PQC `verify()` accepts placeholder | CLOSED | SDK | `sdk/typescript/src/crypto/pqc.ts` @ `6f2fdd8d` | PQC class comment confirms fail-closed design; test verifies `verify()` throws without backend and rejects forged signatures | 2026-02-23 | 2026-03-30 |
| H-08 | INT-2026-002 | High | Cryptographic | Rust pillar placeholders in production | CLOSED | Core Protocol | `crates/core/src/pillars/` @ `6f2fdd8d` | All dev-only paths gated behind `#[cfg(not(feature = "production"))]`; production builds exclude placeholder code | 2026-02-23 | 2026-03-30 |
| H-10 | INT-2026-002 | High | Cryptographic | TypeScript PQC `sign()` generates fake signatures | CLOSED | SDK | `sdk/typescript/src/crypto/pqc.ts` @ `6f2fdd8d` | Class comment: "no longer generates demo signatures"; tests confirm delegation to injected backend | 2026-02-23 | 2026-03-30 |
| H-11 | INT-2026-002 | High | Cryptographic | TypeScript SEV/Nitro verification placeholder | CLOSED | SDK | `sdk/typescript/src/crypto/tee.ts` @ `6f2fdd8d` | `tee.ts` implements real SGX/SEV/TDX/Nitro verification; `NITRO_ROOT_CERT` intentionally empty -- apps must inject real PEM via `TEEVerificationOptions` | 2026-02-23 | 2026-03-30 |
| L-01 | INT-2026-002 | Low | Cryptographic | Token burn floating-point accounting | CLOSED | Core Protocol | `crates/core/src/pillars/` @ `6f2fdd8d` | Pillar module uses integer-based accounting; `quadratic_burn` referenced in `mod.rs` with source-level regression tests | 2026-02-23 | 2026-03-30 |
| L-04 | INT-2026-002 | Low | Cryptographic | `cosine_similarity()` zero denominator | CLOSED | Core Protocol | `crates/core/src/pillars/vector_vault.rs` @ `6f2fdd8d` | `EPSILON: f32 = 1e-12`; `if !denom.is_finite() || denom <= EPSILON { 0.0 }` guard confirmed; `test_cosine_similarity` test present | 2026-02-23 | 2026-03-30 |
| L-07 | INT-2026-002 | Low | Cryptographic | Placeholder Nitro root certificate | CLOSED | SDK | `sdk/typescript/src/crypto/tee.ts` @ `6f2fdd8d` | `NITRO_ROOT_CERT = ''` with comment: "Placeholder certificates are rejected"; apps must inject real cert via options | 2026-02-23 | 2026-03-30 |

---

## Category: Operational

**Scope:** Infrastructure, CI/CD, configuration, process
**Audit engagements:** INT-2026-002, MR-2026-001

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date | Verified |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|----------|
| C-06 | INT-2026-002 | Critical | Operational | Simulated TEE/prover defaults in production compose | CLOSED | Infrastructure | `infrastructure/docker/docker-compose.yml` @ `6f2fdd8d` | Production compose has no SIMULATED env vars; `audit-config-guards.yml` CI workflow in place | 2026-02-23 | 2026-03-30 |
| H-12 | INT-2026-002 | High | Operational | Hardcoded Grafana admin password in compose | CLOSED | Infrastructure | `infrastructure/docker/docker-compose.yml` @ `6f2fdd8d` | Production compose uses `GF_SECURITY_ADMIN_PASSWORD__FILE=/run/secrets/grafana_admin_password` with Docker secrets; devnet compose uses env var with default placeholder | 2026-02-23 | 2026-03-30 |
| M-07 | INT-2026-002 | Medium | Operational | TEE quote-type detection weakness | CLOSED | TEE | `services/tee-worker/nitro-sdk/src/attestation/engine.rs` @ `6f2fdd8d` | `detect_quote_type()` uses Intel header fields (version + att_key_type bytes); tests cover SGX DCAP, SGX EPID, TDX, SEV-SNP, Nitro detection | 2026-02-23 | 2026-03-30 |
| M-09 | INT-2026-002 | Medium | Operational | Devnet unbonding period too low for production | CLOSED | Infrastructure | Devnet `genesis.json` @ `6f2fdd8d` | `scripts/validate-devnet-genesis.py` enforces `MIN_DEVNET_UNBONDING_SECONDS = 259200` (3 days) | 2026-02-23 | 2026-03-30 |
| M-10 | INT-2026-002 | Medium | Operational | Devnet attestation floor mismatch | CLOSED | Infrastructure | Devnet `genesis.json` @ `6f2fdd8d` | `scripts/validate-devnet-genesis.py` enforces `minAttestationsForSeal >= ceil(validators * 0.67)` | 2026-02-23 | 2026-03-30 |
| L-03 | INT-2026-002 | Low | Operational | EPID-specific info leak in error messages | CLOSED | TEE | `services/tee-worker/nitro-sdk/src/attestation/engine.rs` @ `6f2fdd8d` | EPID returns generic "Unsupported attestation quote format"; test asserts `!rendered.to_ascii_lowercase().contains("epid")` | 2026-02-23 | 2026-03-30 |
| L-05 | INT-2026-002 | Low | Operational | `.DS_Store` tracked in repos | CLOSED | All | `.gitignore` @ `6f2fdd8d` | `.DS_Store` entry confirmed in root `.gitignore` | 2026-02-23 | 2026-03-30 |
| L-06 | INT-2026-002 | Low | Operational | Rust `target/` artifacts tracked in git | CLOSED | All | `.gitignore` @ `6f2fdd8d` | `target/` entry confirmed in root `.gitignore` | 2026-02-23 | 2026-03-30 |
| L-08 | INT-2026-002 | Info | Operational | Missing API-key auth header support in SDK | CLOSED | SDK | `sdk/typescript/src/core/client.ts` @ `6f2fdd8d` | `'X-API-Key': this.config.apiKey` header confirmed in HTTP client constructor | 2026-02-23 | 2026-03-30 |
| AETHEL-MR-001 | MR-2026-001 | Critical | Operational | Duplicate chain repos with same Go module path | Partially Remediated | Governance | Authority registry + ADR-0001 prepared | Pending Foundation ratification; cannot close without governance approval | 2026-02-24 | -- |
| AETHEL-MR-002 | MR-2026-001 | Critical | Operational | `aethelred-rust-node` non-buildable repo | Remediated Locally | Core Protocol | `Cargo.toml` + CI added locally | `cargo check --offline` passes locally; pending push to public `aethelred-rust-node` repo | 2026-02-24 | -- |
| AETHEL-MR-003 | MR-2026-001 | Critical | Operational | Audit evidence fragmented outside public repos | Partially Remediated | Security / PMO | Baseline CI added to 9 local clones | Auditability rollout matrix exists but public repos not yet updated | 2026-02-24 | -- |
| AETHEL-MR-004 | MR-2026-001 | High | Operational | Absolute local workstation paths in public docs | Remediated Locally | Docs | Path references replaced | Fix applied locally; pending push to public repos | 2026-02-24 | -- |
| AETHEL-MR-005 | MR-2026-001 | High | Operational | SDKs pending public artifact publication | Partially Remediated | SDK | Provenance controls added | Pending registry publish (npm/crates.io/PyPI) | 2026-02-24 | -- |
| AETHEL-MR-006 | MR-2026-001 | High | Operational | Security workflow targets stale contract paths | Remediated Locally | Security | `security-scans.yml` updated | Fix applied locally; pending push to security-scans repo | 2026-02-24 | -- |
| AETHEL-MR-007 | MR-2026-001 | High | Operational | Threat models/SBOMs not visible per repo | Partially Remediated | Security | `SECURITY.md` + threat model skeletons | Skeletons created; pending completion and per-repo publication | 2026-02-24 | -- |
| AETHEL-MR-008 | MR-2026-001 | Medium | Operational | Dashboard lacks explicit CSP headers | Partially Remediated | Frontend | CSP header added (still has `unsafe-inline`) | CSP confirmed in `dApps/shiora/next.config.js` and `dApps/zeroid/next.config.js` but both still use `'unsafe-inline'` for script-src and style-src; nonce/hash migration required | 2026-02-24 | -- |
| AETHEL-MR-009 | MR-2026-001 | Medium | Operational | Uneven test maturity across repos | Partially Remediated | All Squads | Baseline CI added everywhere | Baseline CI present; enforced test gates and coverage thresholds pending | 2026-02-24 | -- |
| AETHEL-MR-010 | MR-2026-001 | Medium | Operational | `nitro-sdk` `full-sdk` warnings not at zero | Remediated Locally | TEE | Doc comment fix | Fix applied locally; pending push to public `nitro-sdk` repo | 2026-02-24 | -- |

---

## Pending External Audit Findings

### Engagement: AUD-2026-001 (External -- Smart Contracts)

Status: In Progress (started 2026-02-14)

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date | Verified |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|----------|
| _Findings will be added as the audit report is delivered_ | | | | | | | | | | |

### Engagement: AUD-2026-002 (External -- Consensus + Vote Extensions)

Status: In Progress (started 2026-02-14)

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date | Verified |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|----------|
| _Findings will be added as the audit report is delivered_ | | | | | | | | | | |

---

## Pending Merge Hardening Tranche (2026-04-16)

These items are already implemented on public review branches but are not yet
part of the `main`-branch CLOSED statistics below.

| Tracking ID | Severity | Area | Description | Branch / Commit | Verification |
|-------------|----------|------|-------------|-----------------|--------------|
| HS-2026-04-16-01 | High | Bridge (Rust) | Persist relayer state across restarts, require real burn nonces, ceil-round quorum thresholds, reject malformed Ethereum event metadata, and fail closed on placeholder voting and submission paths | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test -p aethelred-bridge` |
| HS-2026-04-16-02 | High | Consensus / VM | Bind TEE attestations to work-result hashes, enforce allowlists, reject invalid challenge responses, and fail closed in WASM verification stubs | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test -p aethelred-vm ...`; `cargo test -p aethelred-consensus ...`; `cargo check -p aethelred-vm` |
| HS-2026-04-16-03 | High | TEE | Make incomplete SGX/Nitro/SEV verifier backends return explicit errors instead of placeholder success | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features attestation-evidence fails_closed_when_backend_missing`; `cargo check --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features attestation-evidence` |
| HS-2026-04-16-04 | High | Smart Contract | Require timelock-first production initialization across bridge, token, vesting, vault, and institutional bridge surfaces | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `forge test --match-path test/AethelredVesting.t.sol`; `npx hardhat test test/institutional.stablecoin.integration.test.ts` |
| HS-2026-04-16-05 | Medium | Smart Contract | Return Cruzible to mainnet-deployable size without weakening core staking or verifier logic | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `npx hardhat size-contracts`; `forge test --match-path test/Cruzible.t.sol`; `forge test --match-path test/CruzibleInvariant.t.sol`; `forge test --match-path test/VaultInvariant.t.sol` |
| HS-2026-04-16-06 | High | Cryptographic / TEE | Replace live placeholder hybrid secp256k1 + Dilithium signing/verification in the worker runtime, align Dilithium wire sizes to the backing library, and move deterministic seed helpers out of production builds | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk hybrid` |
| HS-2026-04-16-07 | High | zkML / TEE | Remove placeholder zk proof generation from the worker runtime and make zk proof generation/verification fail closed until a real EZKL backend is configured | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk zktensor`; `cargo check --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk` |
| HS-2026-04-16-08 | High | Verify Keeper / TEE | Replace keeper-side simulated TEE attestation success-by-structure with an authenticated quote envelope keyed by explicit simulation verifier material, and reject tampered or unsigned simulated attestations | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/verify/keeper/...`; `go test ./x/verify/...` |
| HS-2026-04-16-09 | Medium | zkML / Verify | Replace simulated EZKL verification success-by-structure with deterministic transcript recomputation so tampered simulated proofs and public inputs fail verification | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/verify/...` |
| HS-2026-04-16-10 | Medium | Smart Contract / Governance | Remove deployer-owned bootstrap control from the reserve automation keeper by assigning final ownership at deployment time instead of post-deploy transfer | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `npx hardhat compile`; `npx hardhat test test/institutional.reserve.automation.keeper.test.ts` |
| HS-2026-04-16-11 | Medium | Operational / Governance | Require explicit non-local deployment authorities across bridge, keeper, and Cruzible deployment scripts so production deployments fail closed instead of inheriting deployer control or silently backfilling governance participants | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `npx hardhat test test/deployment.governance.config.test.ts test/institutional.reserve.automation.keeper.test.ts` |
| HS-2026-04-16-12 | High | Seal / Verification | Make digital seal TEE and zk verification fail closed by default unless explicit verifier backends are configured, keeping structural-only checks behind an insecure test-only opt-in | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/seal/keeper/...` |
| HS-2026-04-16-13 | High | Mempool / Cryptographic | Replace format-only hybrid signature acceptance in the active mempool middleware with real hybrid signature verification, sender derivation binding, and tamper-rejecting regression coverage | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test -p aethelred-mempool` |
| HS-2026-04-16-14 | High | VM / Verification | Make the VM job registry fail closed on invalid or unavailable TEE and zk verification precompile results for mainnet/testnet configs, while preserving an explicit devnet-only permissive lane | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test -p aethelred-vm job_registry` |
| HS-2026-04-16-15 | High | VM / TEE | Make the live TEE precompile registry secure-by-default, isolate permissive structural-only paths behind explicit devnet constructors, and fail closed on missing SGX/Nitro/SEV cryptographic backends at the platform-specific precompile addresses | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test -p aethelred-vm precompiles::tee::tests` |
| HS-2026-04-16-16 | Medium | Verify Keeper / zkML | Replace simulated keeper-side zk proof acceptance-by-length with deterministic proof binding to the verifying key, circuit hash, and public inputs, and add tamper-rejecting regression coverage | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/verify/keeper/...`; `go test ./x/verify/...` |
| HS-2026-04-16-17 | High | Sovereign / TEE | Replace sovereign protected/private/secret plaintext-at-rest behavior with owner-bound authenticated encryption, require owner-backed decryption for encrypted payloads, enforce access-purpose requirements, and reject debug-mode or unacceptable-TCB enclave reports for TEE-only data | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk lib_full::sovereign::`; `cargo check --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk` |
| HS-2026-04-16-18 | High | Validator / Slashing | Require validator slashing to invoke real staking slash/jail hooks when configured, and fail closed instead of recording local-only penalties when the economic penalty path cannot be resolved | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/validator/keeper` |
| HS-2026-04-16-19 | High | Seal / Governance | Replace event-only seal revocation approval/execution with a stored request state machine that enforces approval thresholds, dispute blocking, dispute-resolution state transitions, and fail-closed execution semantics | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/seal/keeper` |
| HS-2026-04-16-20 | Medium | App / TEE | Make safe app initialization fail closed for real verifier-backed TEE modes (`remote`, `http`, `nitro`, `aws-nitro`) instead of classifying them as degradable startup failures when the TEE client cannot be initialized | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app -run 'Test(TeeModeRequiresHealthyVerifier|SafeInitTEEClient_.*|NewApp_NoPanic)$'` |
| HS-2026-04-16-21 | Medium | App / TEE | Make the explicit `nitro-simulated` app client identify itself as simulated, emit schema-consistent Nitro quote JSON with a simulation signature, generate zk proof artifacts that satisfy app-layer validation, and keep the orchestrator on the intended simulated verifier path | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app` |
| HS-2026-04-16-22 | High | Nitro / Confidentiality | Replace base64-wrapped plaintext in Nitro `EncryptForEnclave(...)` with authenticated encryption for simulated Nitro, and fail closed for remote Nitro until a real attested enclave public-key encryption path is available | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/verify/tee ./services/tee-worker/l1-verifier` |
| HS-2026-04-16-23 | Medium | Seal / Signatures | Make seal signature checks fail closed when signatures are present but no verifier backend exists, instead of treating the presence of signature bytes as successful cryptographic verification | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/seal/keeper` |
| HS-2026-04-16-24 | Medium | Seal / Export Provenance | Make seal export signing fail closed unless a real export signer backend is configured, instead of exposing `AddExportSignature` as a non-enforced provenance control | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/seal/keeper` |
| HS-2026-04-16-25 | Medium | App / PQC Readiness | Replace the placeholder PQC availability check with mode-aware backend validation so production and hybrid PQC startup requests reflect actual CIRCL availability instead of unconditional success | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app` |
| HS-2026-04-16-26 | Medium | Seal / Enhanced Provenance | Make enhanced seal verification fail closed when envelope signatures are present but no enhanced-signature verifier backend exists, instead of ignoring the richer signature surface entirely | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/seal/keeper` |
| HS-2026-04-16-27 | Medium | Seal / Import Provenance | Make seal export import fail closed on content-hash mismatch or unverifiable attached signatures, instead of trusting decoded signed exports without checking the recorded provenance controls | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/seal/keeper` |
| HS-2026-04-16-28 | Medium | App / PoUW / TEE Taxonomy | Align simulated TEE platform handling across the app vote-extension verifier and PoUW keeper so `nitro-simulated` and `mock-tee` are consistently recognized as simulated-only aliases and unknown platform names are rejected instead of slipping through application-level verification | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app -run 'TestVoteExtensionVerifier(RejectsUnknownTEEPlatform|AcceptsNitroSimulatedTEEPlatform)$'` and `go test ./x/pouw/keeper -run 'TestProduction_(RejectsSimulatedTEEPlatform|RejectsAllSimulatedTEEPlatformAliases|RejectsSimulatedTEEInHybrid|AcceptsRealTEEPlatforms)$'` |
| HS-2026-04-16-29 | Medium | App / Consensus Ingress | Bind ABCI vote-extension validator identity and height to the authoritative `RequestVerifyVoteExtension` request so mismatched embedded payloads are rejected before staking lookup or signature verification instead of relying on later keeper-side cross-checks | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app -run 'TestVerifyVoteExtensionHandlerRejects(MismatchedValidatorAddress|MismatchedHeight)$'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` |
| HS-2026-04-16-30 | High | PoUW / Governance Controls | Enforce the mainnet lock registry in the live `UpdateParams` execution path and align compatibility/proposal tooling with that runtime policy so locked governance fields fail closed instead of relying on advisory lock metadata or non-attestable elevated-quorum assumptions | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/pouw/keeper -run 'Test(UpdateParams|CB7_UpdateParams|ParamChangeProposal|Mainnet)'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` |
| HS-2026-04-16-31 | Medium | PoUW / Audit Readiness | Align the verification-policy assessment and audit checklist with the live governance lock enforcement so audit-facing readiness logic proves runtime change control instead of treating lock-registry metadata alone as sufficient evidence | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/pouw/keeper -run 'Test(EvaluateVerificationPolicy|AuditChecklist|FullSecurityComplianceFlow|SecurityComplianceWithCorruptedState)'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` |
| HS-2026-04-16-32 | Medium | PoUW / Attestation Registry | Make privileged trusted-measurement registry mutations emit explicit runtime events and structured audit records, reconcile Nitro legacy PCR0 indexing during authority appends, and reject measurement revocations only when neither the global registry nor the legacy compatibility index contains the target measurement | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/pouw/keeper -run 'TestAttestationRegistry_(AppendTrustedMeasurement_AuditsAndReconcilesLegacyNitroIndex|RevokeTrustedMeasurementBySecurityCommittee_AuditsAndRemovesIndexes|RevokeTrustedMeasurementBySecurityCommittee_RejectsUnknownMeasurement|RegisterAndValidatePCR0|RegisterAndValidateSGXMRENCLAVE)|TestCB(5|6|7)_(AppendTrustedMeasurement|RevokeTrustedMeasurement)'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` |
| HS-2026-04-16-33 | Medium | PoUW / Security Audit Surface | Align the built-in security audit runner and threat-model narratives with the hardened production governance posture so the repo’s own audit tooling enforces the `67%+` production consensus floor and documents the live `UpdateParams` one-way gate and implemented vote-extension signing path instead of older `MergeParams` or TODO-era descriptions | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/pouw/keeper -run 'Test(AuditRunner_BadParams_(LowConsensusThreshold|BelowProductionConsensusFloor)|AuditRunner_CleanState_.*|ThreatModel_.*|SecurityProperty_OneWayGate.*)'` and `go test ./x/pouw/keeper` |
| HS-2026-04-16-34 | High | PoUW / Emergency Governance | Replace single-member trusted-measurement emergency revocation with a bonded-validator quorum workflow that persists revocation requests, deduplicates approvals, executes only after two independent committee approvals, and fails closed when the committee cannot satisfy that quorum safely | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/pouw/keeper -run 'TestAttestationRegistry_(RequiresMultiApprovalAndAuditsLifecycle|RequiresMultiMemberCommittee|RejectsUnknownMeasurement|AppendTrustedMeasurement_AuditsAndReconcilesLegacyNitroIndex|RegisterAndValidatePCR0|RegisterAndValidateSGXMRENCLAVE)|TestCB(5|6|7)_(AppendTrustedMeasurement|RevokeTrustedMeasurement)'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` |
| HS-2026-04-16-35 | High | Seal / Governance Controls | Remove the ordinary privileged seal-revocation bypass by forcing admin-level authorities off the direct revoke helper and direct message path, narrow the raw keeper revoke path to an internal self-revocation helper, raise the default privileged threshold to multi-party approval, and confine forced direct revocation to the explicit emergency lane with mandatory justification on both single and batch entrypoints | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/seal/keeper` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` |
| HS-2026-04-16-36 | High | Seal / Emergency Governance | Replace single-signer emergency seal revocation with a quorumed break-glass workflow that stores emergency approval state, rejects duplicate approvals, restricts emergency execution to urgent reasons, blocks emergency requests from slipping into the ordinary dispute path, and applies the same per-seal quorum semantics to emergency batch revocation | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/seal/keeper` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` |
| HS-2026-04-16-37 | High | Vault / Governance Controls | Enforce module-authority checks directly on governance-only vault keeper methods for vendor-root keys, enclave and operator lifecycle, and attestation-relay registration / rotation / revocation so privileged state changes no longer rely on comment-level restrictions or caller discipline | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/vault/keeper` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` |
| HS-2026-04-16-38 | Medium | Vault / Relay Governance | Enforce module authority on attestation-relay liveness challenge issuance, reject silent overwrite of live challenges, clear expired challenge state deterministically before rollover, and record challenge issuance / successful response in the operator audit log so relay liveness governance no longer relies on comment-level issuance semantics | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./x/vault/keeper` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` |
| HS-2026-04-16-39 | Medium | App / Admin Surface | Enforce a real security boundary on `/admin/consensus/evidence/audit` by making it loopback-only by default, allowing deliberate remote exposure only through an explicit bearer token, and rejecting oversized request bodies before decode so the admin route no longer behaves like an unauthenticated remote audit surface | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` |
| HS-2026-04-16-40 | Medium | App / Observability Truthfulness | Make `/health/aethelred` report simulated and degraded verification posture honestly instead of collapsing allowed simulation into `healthy`, and reserve `503` for genuinely unhealthy overall runtime states so operational health claims match enforced verification posture | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` |
| HS-2026-04-16-41 | Medium | App / Operational Surface | Enforce a real handler-level boundary on `/metrics/aethelred` by making it `GET`-only, loopback-only by default, and remotely accessible only through an explicit bearer token, while unifying route-boundary auth for metrics and admin operational endpoints under the same shared loopback-or-token model | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` |
| HS-2026-04-16-42 | Medium | App / Information Disclosure | Keep `/health/aethelred` usable as a public liveness surface while restricting detailed chain metadata, readiness internals, component messages, and capability payloads to loopback or explicit token authorization so the health route no longer acts as a remote diagnostic disclosure surface | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` |
| HS-2026-04-16-43 | Medium | App / Proxy Boundary | Tighten the shared loopback-or-token guard so proxied requests carrying forwarding headers cannot inherit unauthenticated loopback trust for `/admin/consensus/evidence/audit`, `/metrics/aethelred`, or detailed `/health/aethelred` diagnostics, forcing those operational surfaces onto the explicit bearer-token path whenever they cross a proxy boundary | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` |
| HS-2026-04-16-44 | Medium | App / Remote TEE Boundary | Fail closed on unsafe remote TEE endpoint configuration by validating the configured endpoint during `RemoteTEEClient` construction and enforcing the same SSRF guard on the health probe path that already protected execution and capability fetches, so real remote TEE startup and liveness checks cannot succeed on blocked or malformed outbound targets | `ramesh/protocol-hardening-sweep-20260416` / PR `#141` | `go test ./app` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` |

See `docs/audits/protocol-hardening-sweep-2026-04-16.md` for the detailed
scope and verification record.

---

## Aggregate Statistics

### By Severity (All Engagements)

| Severity | Total | Open | In Progress | CLOSED | Partially Remediated | Remediated Locally | Accepted Risk | Disputed |
|----------|------:|-----:|------------:|-------:|---------------------:|-------------------:|--------------:|---------:|
| Critical | 10 | 0 | 0 | 7 | 2 | 1 | 0 | 0 |
| High | 16 | 0 | 0 | 12 | 2 | 2 | 0 | 0 |
| Medium | 13 | 0 | 0 | 9 | 3 | 1 | 0 | 0 |
| Low/Info | 8 | 0 | 0 | 8 | 0 | 0 | 0 | 0 |
| **Total** | **47** | **0** | **0** | **36** | **7** | **4** | **0** | **0** |

### By Category

| Category | Total | CLOSED | Partially Remediated | Remediated Locally | Open |
|----------|------:|-------:|---------------------:|-------------------:|-----:|
| Smart Contract | 16 | 16 | 0 | 0 | 0 |
| Consensus | 4 | 4 | 0 | 0 | 0 |
| Cryptographic | 8 | 8 | 0 | 0 | 0 |
| Operational | 19 | 8 | 7 | 4 | 0 |
| Bridge (Rust) | 0 | 0 | 0 | 0 | 0 |
| **Total** | **47** | **36** | **7** | **4** | **0** |

### Notes

- All 36 findings from INT-2026-002 and the 1 finding from CON-2026-001 have been verified against source code on the `main` branch (`6f2fdd8d`) and are now CLOSED (2026-03-30).
- 7 findings remain "Partially Remediated" -- these are multi-repo governance/process findings (AETHEL-MR series) that require Foundation ratification, public repo pushes, or registry publication.
- 4 findings are "Remediated Locally" -- fixes exist in local clones but have not been pushed to their respective public repositories.
- 2 external audit engagements (AUD-2026-001, AUD-2026-002) are in progress; findings will be added when reports are delivered.
- AETHEL-MR-008 was re-verified: CSP headers are present in both dApps but still contain `'unsafe-inline'`; nonce/hash migration is required to fully close.

---

## Accepted-Risk Rationale Template

When a finding is marked as **Accepted Risk**, copy this template and fill it in as a new section below.

### [Finding ID]: [Brief Description]

| Field | Value |
|-------|-------|
| **Finding ID** | e.g., `M-XX` |
| **Source** | Audit engagement ID |
| **Severity** | Critical / High / Medium / Low |
| **Category** | Smart Contract / Consensus / Bridge / Cryptographic / Operational |
| **Description** | Full description of the finding |
| **Risk Assessment** | Detailed assessment of the residual risk if unresolved |
| **Business Justification** | Why accepting this risk is the appropriate decision |
| **Compensating Controls** | What mitigations are in place to reduce the residual risk |
| **Monitoring** | How the risk will be monitored going forward |
| **Review Date** | When the accepted risk will next be reviewed |
| **Approved By** | Name and role of the approver |
| **Approval Date** | Date of approval |

**Example:**

### AR-001: Example Accepted Risk

| Field | Value |
|-------|-------|
| **Finding ID** | M-99 |
| **Source** | AUD-2026-001 |
| **Severity** | Medium |
| **Category** | Smart Contract |
| **Description** | Example: Gas optimization in rarely-called admin function exceeds recommended threshold |
| **Risk Assessment** | Function is called <1x/month by multisig; gas cost is borne by protocol treasury, not end users |
| **Business Justification** | Refactoring would require a storage layout migration that introduces upgrade risk greater than the gas cost |
| **Compensating Controls** | (1) Function is behind 3-of-5 multisig. (2) Gas monitoring alert triggers if cost exceeds 2x baseline. (3) Upgrade path documented for future optimization |
| **Monitoring** | Monthly gas cost review in ops dashboard |
| **Review Date** | 2026-06-25 (90-day review) |
| **Approved By** | Security Lead |
| **Approval Date** | YYYY-MM-DD |

---

## Template: Adding a New Finding

Copy and paste this row into the appropriate category table:

```
| FINDING-ID | SOURCE-ENGAGEMENT | Severity | Category | Brief description | Open | Squad Name | | | YYYY-MM-DD | |
```

Update the aggregate statistics tables when adding or changing finding status.

---

## References

- Evidence index: [`docs/audits/EVIDENCE_INDEX.md`](EVIDENCE_INDEX.md)
- Scope map: [`docs/audits/SCOPE_MAP.md`](SCOPE_MAP.md)
- Audit status tracker: [`docs/audits/STATUS.md`](STATUS.md)
- Full audit v2 matrix: [`docs/audits/aethelred-full-audit-report-v2-remediation-matrix.md`](aethelred-full-audit-report-v2-remediation-matrix.md)
- Multi-repo disposition: [`docs/audits/aethelred-multi-repo-findings-disposition-2026-02-24.md`](aethelred-multi-repo-findings-disposition-2026-02-24.md)
- Retest checklist: [`docs/audits/aethelred-v2-retest-checklist.md`](aethelred-v2-retest-checklist.md)
