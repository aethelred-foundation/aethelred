# CEAP Threat Model — Confidential Execution & Attestation Protocol

Status: living document, maintained with the code it describes.
Scope: the CEAP surface introduced by ADR-0003 and its EVM exposure (ADR-0001):
`internal/confidential`, `internal/evmhost`, `precompiles/{seal,verify,pouw}`,
`x/pouw/keeper/confidential.go`, `x/verify/confidential.go`, and the
seal-binding path in `x/pouw/keeper.CompleteJob`.

This document is written for an external security review (Trail of Bits /
OpenZeppelin-class). Every claim in it is enforced by code referenced inline
and, where stated, proven by a test or fuzz harness in the repository. Claims
we cannot yet enforce are listed under **Known limitations** — the protocol's
honesty boundary is that no such claim is ever presented as enforced.

---

## 1. System overview

A client submits a PoUW job with an optional **ConfidentialityPolicy**
(allowed backends, minimum verification method, allowed platforms,
vendor-root requirement, data residency). A worker executes the job inside a
**confidentiality backend** (TEE / GPU-CC / MPC / FHE), producing a
**ConfidentialityAttestation**. Consensus re-derives the attestation from
consensus-agreed verification results, enforces `Satisfies(policy)` **before
any state write**, and binds the attestation into the PQC **Digital Seal**,
folding it into the tamper-evident seal ID. Contracts read and gate on the
attestation through the **ISeal precompile** with the same `Satisfies` logic.

Two orthogonal dimensions are attested independently and never conflated:

| Dimension | Values (weak → strong) |
|---|---|
| Confidentiality backend | none → TEE/GPU-CC → MPC → FHE → Hybrid |
| Verification method | none → tee-attested → freivalds → optimistic → reexec → zkml |

A zkML proof does **not** imply confidentiality (it proves correctness of a
public computation); an FHE execution does **not** imply correctness (it hides
data without proving the result). `internal/confidential/derive.go` encodes
this separation.

## 2. Assets

1. **Client input data** (may be regulated: PHI, PII, financial records).
2. **Digital Seal integrity** — the seal is the product sold to regulators; a
   forged or wrongly-attested seal is the worst-case loss.
3. **Model weights** (commercially sensitive; committed by hash on-chain).
4. **Consensus liveness/safety** — determinism of every consensus-path
   computation; a panic or divergence in CEAP code halts the chain.
5. **Reward pool funds** (PoUW verification rewards, slashing).

## 3. Trust boundaries and adversaries

| Boundary | Adversary considered |
|---|---|
| Client ↔ worker | Malicious worker: reads plaintext, fabricates results/attestations |
| Worker ↔ consensus | Malicious validator minority: false verification results, replayed attestations |
| Consensus ↔ contract (EVM) | Arbitrary attacker: hostile calldata to permissionless precompiles |
| Chain operator ↔ deployment | Dishonest operator: misconfigures a deployment to overclaim (e.g. simulated TEE presented as production) |
| MPC parties | Coalition of up to n−1 parties (semi-honest); the colocation case (one operator = all parties) |
| External network | Malformed/adversarial bytes on every deserialization surface |

Out of scope (chain-level, covered elsewhere): >⅓ Byzantine validator power,
CometBFT consensus attacks, key custody of validator PQC keys.

## 4. Security invariants (enforced, with evidence)

**I1 — Never downgrade.** If no operational backend satisfies the policy, the
job is rejected; the network never silently substitutes a weaker backend.
Enforced in `Registry.Select` (`internal/confidential/backend.go`); proven by
`TestRegistry_SelectHonoursPolicyAndAvailability`, `TestFHE_RegistrySelectsStrongest`.

**I2 — Fail closed.** Policy checks reject on any missing capability: platform
pinned but attestation has no platform (FHE/MPC), vendor root required but
trust basis is a test root, residency demanded but jurisdiction empty.
Enforced in `ConfidentialityAttestation.Satisfies` (`policy.go`); proven by
`TestSatisfies_Rejections`, `TestSatisfies_PlatformAndResidencyRejections`.

**I3 — Enforce before write.** `CompleteJob` derives and checks the
attestation **before** the first state mutation; a non-compliant job is never
sealed and never transitions to COMPLETED. Proven by
`TestCompleteJob_RejectsPolicyViolation` (asserts no seal exists and status is
unchanged after rejection).

**I4 — Determinism on the consensus path.** The consensus-side derivation
(`DeriveAttestation`) is a pure fold over consensus-agreed inputs
(attestation types, platforms, on-chain params); it reads no clocks, no
randomness, no local configuration. All timestamps written in `CompleteJob`
come from block time. Regression history: wall-clock timestamps previously
caused AppHash divergence (fixed and tested at the multi-node level).

**I5 — No panic on adversarial input.** Every deserialization surface that
accepts untrusted bytes converts malformed input into an error:
- Precompile calldata: `FuzzPrecompileRun` (≈133k execs/10s, 0 panics).
- FHE ciphertexts: lattigo's `UnmarshalBinary` panics on hostile bytes; the
  recover guard `safeUnmarshalCiphertext` converts this to an error.
  `FuzzSafeUnmarshalCiphertext` (0 panics).
- MPC share bundles: shape header validated against payload length with
  plausibility bounds (n ≤ 1024, dim ≤ 2^20) before allocation.
  `FuzzUnmarshalShareBundle` (≈1.4M execs/10s, 0 panics) additionally asserts
  accepted bundles are internally consistent.
- FHE result frames: `FuzzReadCiphertextFrames` (0 panics).

**I6 — Tamper-evident binding.** The confidentiality attestation is folded
into the seal ID hash (`GenerateID`, domain-separated, fixed field order);
altering any attested field changes the ID. Guarded on presence so pre-CEAP
seal IDs are unchanged. Proven by `TestCompleteJob_BindsConfidentialityAttestation`
(asserts `seal.Id == seal.GenerateID()` after binding).

**I7 — Consensus-parity gating in the EVM.** The ISeal precompile's
`requireConfidentiality` executes the same `Satisfies` code path consensus ran
at sealing — not a reimplementation. A contract can therefore not be told
"yes" for a policy consensus would have rejected. Proven by
`TestPrecompile_RequireConfidentiality` and the end-to-end
`TestHost_ContractCallsPrecompile` (real interpreter, real bytecode).

**I8 — Deployment honesty.**
- A chain permitting simulated TEE (`Params.AllowSimulated = true`) derives
  `test_root`, never `vendor_root` (`trustBasisFromParams`); a vendor-root
  policy is unsatisfiable on such a chain. Proven by
  `TestCompleteJob_VendorRootPolicyRejectedOnSimulatedChain`.
- A colocated MPC cluster reports `DataSealed = false` (one operator holds all
  shares — no secrecy claim). Proven by `TestMPC_BackendHonesty`.
- GPU-CC availability is driven by live hardware detection (`nvidia-smi
  conf-compute`), never configuration. Proven by
  `TestGPUCC_ProductionDetectorHonesty` (asserts unavailability on non-CC hosts).
- Config-less FHE/MPC/GPU-CC constructors report not-operational and are never
  selected.

**I9 — Worker pre-flight.** The orchestrator runs `Satisfies` against the
produced attestation before submitting (`ExecuteConfidential`), so an honest
worker never submits a result consensus must reject. Proven by
`TestExecuteConfidential_ColocatedMPCPreFlightRejected`.

**I10 — No uncommitted weights.** FHE/MPC engines execute only models whose
canonical hash matches the caller's `ModelRef` (`checkModelRef`); a backend
never runs weights the chain did not commit to. Proven by
`TestFHE_EvaluateErrors`, `TestCheckModelRef`.

**I11 — Read-only precompiles.** ISeal/IVerify/IPoUW expose no state
mutation; writes are chain transactions with full ante-handler validation.
Heavy cryptography (pairing checks) is never executed synchronously inside a
precompile (DoS surface — ADR-0001 decision).

## 5. Cryptographic parameters (reviewable)

- **FHE:** CKKS (Lattigo v6), LogN = 13, LogQP = 55+45+61 = 161 ≤ 218 — the
  homomorphicencryption.org 128-bit bound for N = 8192. Parameter hash is part
  of the attestation measurement. Honest scope: depth-1 (linear/affine
  models); the engine rejects anything else.
- **MPC:** n-of-n additive sharing over Z_2^64, fixed-point 2^16 (products at
  2^32; overflow analysis: |w|,|x| ≲ 2^10 keeps products ≪ 2^63). Shares from
  `crypto/rand`. Security: semi-honest, privacy vs n−1 colluding parties;
  **no** malicious-majority claim.
- **Seal ID:** SHA-256, domain-separated (`aethelred_seal_id_v2:`, CEAP fields
  under `ceap/v1:`), fixed-width big-endian integer encoding.
- **Policy hash:** SHA-256 over a canonical, order-normalized encoding
  (`ceap/v1;` prefix); order-insensitivity proven by
  `TestCanonicalHash_StableAndOrderInsensitive`.

## 6. Known limitations / accepted risks (the honesty ledger)

| # | Limitation | Status |
|---|---|---|
| L1 | **MPC topology is worker-asserted.** Consensus cannot yet verify remotely that an "mpc" result came from genuinely independent operators; the worker pre-flight keeps honest workers honest. Mitigation on the roadmap: per-party attestations. | Documented in `derive.go`; not presented as enforced |
| L2 | **FHE proves confidentiality, not correctness.** `Verification = none`; a policy needing both must demand a verification method on top. | Encoded in the type system |
| L3 | **Colocated MPC gives zero confidentiality.** Deliberate: `DataSealed=false`. | Enforced (I8) |
| L4 | **EVM transaction hosting not yet live.** Precompiles are proven against the embedded interpreter; cosmos/evm requires SDK ≥ v0.53 (now satisfied) and lands as a planned integration. Until then no permissionless EVM calldata reaches the precompiles in production. | ADR-0001 Phase 1 note |
| L5 | **TEE quote validation trust roots.** Simulated platforms are fail-closed behind `AllowSimulated` (enterprise genesis validation forbids it); production pinning of vendor roots is deployment configuration. | `x/verify/tee`, `x/pouw` genesis validation |
| L6 | **zkML pairing + TEE hardware gaps** carried from the audit-readiness review remain the two known HIGH-severity deferrals at the platform level (tracked outside CEAP). | Tracked |

## 7. DoS and resource-exhaustion analysis

- Precompile gas: flat per-method costs (2000–5000) charged before execution;
  unknown selectors cost 0 and revert.
- MPC bundle parsing bounds allocations (n ≤ 1024, dim ≤ 2^20, exact length
  check) **before** allocating.
- FHE `Evaluate` work is bounded by registered model dimensions (validated at
  registration against slot capacity); ciphertext deserialization is
  recover-guarded.
- The verification orchestrator carries circuit breakers and caches
  (pre-existing); confidential execution adds one counter under the existing
  metrics mutex.

## 8. Audit entry points

| Surface | Code | Tests |
|---|---|---|
| Policy semantics | `internal/confidential/policy.go` | `policy_test.go`, `coverage_test.go` |
| Consensus derivation | `internal/confidential/derive.go`, `x/pouw/keeper/confidential.go` | `derive_test.go`, `x/pouw/keeper/confidential_test.go` |
| Seal binding | `x/pouw/keeper/keeper.go` (CompleteJob), `x/seal/types/seal.go` (GenerateID) | `confidential_integration_test.go` |
| FHE engine | `internal/confidential/fhe.go` | `fhe_test.go`, `FuzzSafeUnmarshalCiphertext` |
| MPC engine | `internal/confidential/mpc.go` | `mpc_test.go`, `FuzzUnmarshalShareBundle` |
| GPU-CC gating | `internal/confidential/gpucc.go` | `gpucc_test.go` |
| Precompiles | `precompiles/{seal,verify,pouw}`, shared guards in `precompiles/internal/prec` | per-package tests, `FuzzPrecompileRun` |
| EVM host | `internal/evmhost` | `evmhost_test.go` (real bytecode round-trips) |
| Worker path | `x/verify/confidential.go` | `x/verify/confidential_test.go` |

Coverage discipline: every reachable statement is covered; the only uncovered
lines are defensive branches on infallible operations (embedded compile-time
ABI parse, `crypto/rand` failure, in-memory store constructors), each noted in
the package's tests.
