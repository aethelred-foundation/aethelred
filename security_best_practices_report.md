# Aethelred Security Audit Report (Stringent External Review)

Date: 2026-03-02  
Reviewer mode: Adversarial audit (Trail of Bits / OpenZeppelin / CertiK style)  
Scope reviewed: Go L1 node/module paths (`app`, `x/verify`, `x/pouw`), Solidity contracts under `contracts/`, deployment config/scripts.

## Executive Summary

This review identified **7 findings**:

- **1 Critical**
- **3 High**
- **3 Medium**

The most severe issue is a **compute-job fee enforcement bypass** in the ante pipeline: job-specific fees are intended but not actually enforced due to an interface mismatch. This undermines anti-spam economics and can be used to push expensive useful-work jobs at near-minimal tx cost.

Secondary high-risk issues include signature-domain replay risk in `SealVerifier`, mutable seal attestation state in the legacy bridge contract path, and use of a known default private key in deployment config that can leak into non-dev operations.

---

## Findings

### C-01: Compute Job Fee Enforcement Bypass in Ante Handler

**Severity:** Critical  
**Impact:** Economic security bypass, spam amplification, validator resource exhaustion

**Evidence**

- Fee decorator expects tx messages implementing:
  - `GetModelHash() []byte`
  - `GetRequestedBy() string`
  - `GetFee() sdk.Coin`
  - (`app/ante.go`, lines 77-81)
- Actual `MsgSubmitJob` does **not** implement `GetRequestedBy()` or `GetFee()`:
  - `x/pouw/types/pouw.pb.go`, lines 1139-1254
- `GetRequestedBy()` and `GetFee()` exist on `ComputeJob` state objects, not tx messages:
  - `x/pouw/types/pouw.pb.go`, lines 410 and 487

**Why this is exploitable**

`MsgSubmitJob` fails the type assertion in `ComputeJobFeeDecorator`, so the fee-collection branch is skipped. Attackers can submit useful-work jobs without paying intended module job fees.

**Recommendation**

- Replace ad-hoc interface assertion with explicit message type handling (`*types.MsgSubmitJob`).
- Enforce fee source as signer (`msg.Creator`) and remove any user-supplied payer field ambiguity.
- Add regression tests proving:
  - fee is charged for `MsgSubmitJob`
  - job submission fails when fee is below minimum
  - non-job messages are unaffected.

---

### H-01: `SealVerifier` Signatures Lack Domain Separation (Cross-Chain/Contract Replay Risk)

**Severity:** High  
**Impact:** Valid signatures can be replayed across deployments/chains if validator sets overlap

**Evidence**

- Signed payload excludes `block.chainid` and `address(this)`:
  - `contracts/bridges/SealVerifier.sol`, lines 165-174

**Why this matters**

Without domain separation, signatures valid for one verifier deployment can be accepted on another contract/chain with the same validator set and message fields.

**Recommendation**

- Move to EIP-712 typed data with domain (`name`, `version`, `chainId`, `verifyingContract`).
- Include anti-replay fields (epoch/nonce/deadline) in signed struct.

---

### H-02: Mutable `sealId` Mapping in Legacy Bridge Seal Verification

**Severity:** High  
**Impact:** Historical seal data can be overwritten, breaking immutability assumptions for downstream consumers

**Evidence**

- `verifySeal` writes directly to `sealAttestations[sealId]` without preventing overwrite:
  - `contracts/bridges/AethelredBridge.sol`, lines 376-418 and 407-415

**Why this matters**

A previously verified `sealId` can be replaced by a later quorum submission with different data, invalidating “once verified, forever stable” assumptions in integrated systems.

**Recommendation**

- Add one-time-write guard:
  - `require(!sealAttestations[sealId].verified, "...already verified")`
- If updates are required by design, version seals explicitly and expose immutable event-linked history.

---

### H-03: Known Default Private Key Used as Fallback Across Networks

**Severity:** High  
**Impact:** Accidental deployment/signing with publicly known key; potential loss of admin/control funds

**Evidence**

- Hardcoded Anvil private key fallback:
  - `contracts/hardhat.config.ts`, lines 31-33
- Same `PRIVATE_KEY` used for `devnet`, `sepolia`, and `mainnet` accounts:
  - `contracts/hardhat.config.ts`, lines 127-153

**Why this matters**

Operational misconfiguration (missing env var) can silently use the known key in non-local environments.

**Recommendation**

- Fail hard for non-local networks when `DEPLOYER_PRIVATE_KEY` is unset.
- Allow default key only when `network.name` is explicitly local (`hardhat`/`devnet`) and chain ID is local.

---

### M-01: Missing Endpoint Safety Validation in Nitro Remote Calls

**Severity:** Medium  
**Impact:** SSRF/internal network reachability and unexpected trust boundary expansion

**Evidence**

- Remote endpoints are used directly from config:
  - `x/verify/tee/nitro.go`, lines 429 and 484
- No `validateEndpointURL` equivalent call in this path.

**Why this matters**

A compromised/misconfigured endpoint value can direct validator nodes to internal services or non-approved hosts.

**Recommendation**

- Reuse hardened endpoint validation before all outbound calls.
- Enforce HTTPS for non-loopback, deny private/link-local CIDRs after DNS resolution, block metadata endpoints.

---

### M-02: Unbounded Error-Body Reads in Remote Verifier/Prover Code Paths

**Severity:** Medium  
**Impact:** Memory pressure / DoS if remote endpoint returns very large error body

**Evidence**

- Nitro verifier/executor reads full error body:
  - `x/verify/tee/nitro.go`, lines 457 and 512
- EZKL prover/verifier reads full error body:
  - `x/verify/ezkl/prover.go`, lines 601 and 665

**Why this matters**

`io.ReadAll` on untrusted remote responses can allocate arbitrarily large memory buffers.

**Recommendation**

- Use `io.LimitReader` (e.g., 4KB-16KB) for all error-body reads.
- Apply maximum JSON body size limits for success responses as well.

---

### M-03: SSRF Filter in `validateEndpointURL` Is Prefix-Based and DNS-Blind

**Severity:** Medium  
**Impact:** SSRF bypass via DNS indirection/non-canonical host forms

**Evidence**

- Host blocking is string-prefix based, not post-resolution IP validation:
  - `x/verify/keeper/http_security.go`, lines 65-75

**Why this matters**

A hostname resolving to private/link-local ranges can bypass simple string checks.

**Recommendation**

- Resolve hostnames and validate every returned IP against deny ranges.
- Normalize/parse IPv4/IPv6 forms (`netip`) before policy checks.

---

## Notes on Scope

- This repository contains both a hardened production bridge path (`contracts/contracts/AethelredBridge.sol`) and a separate legacy/example bridge path (`contracts/bridges/*`). Findings H-01/H-02 are on the `contracts/bridges` path; if these contracts are not deployed, treat as pre-deployment hardening requirements.
- Review was static/manual in this pass (no full-chain adversarial simulation).

## Recommended Priority Remediation Plan

1. **Immediate (P0):** Fix C-01 fee bypass and ship regression tests.
2. **Short-term (P1):** Remove production default key fallback; patch signature domain separation and seal immutability where deployed.
3. **Short-term (P1/P2):** Add endpoint allowlist + bounded response reads in all remote verifier/prover paths.
4. **Defense-in-depth:** Unify outbound HTTP security policy in one reusable package and enforce it from all modules.

