# Aethelred Verification Policy

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-02-05
**Owner**: Security / Platform Lead

---

## 1. Purpose

This document defines the security policy governing how AI computation
verification is performed across all Aethelred network environments. It
codifies the invariants that must hold for every block, every vote
extension, and every Digital Seal produced by the network.

The policy is the single source of truth for:
- Which verification modes are permitted in which environments.
- What constitutes a valid attestation or proof.
- How the consensus layer gates simulated vs. production verification.
- Fail-closed semantics enforced at each layer.

---

## 2. Environments

| Environment | Chain ID Pattern         | `AllowSimulated` | Real Verifier Required | Notes |
|-------------|--------------------------|-------------------|------------------------|-------|
| **Mainnet** | `aethelred-mainnet-1`            | `false`           | Yes                    | Full production security |
| **Testnet** | `aethelred-testnet-*`    | `false`           | Yes                    | Mirror mainnet policy |
| **Devnet**  | `aethelred-devnet-*`     | `true` (optional) | No                     | Development iteration |
| **Localnet**| `aethelred-local-*`      | `true`            | No                     | Single-validator testing |

> **Rule**: Any chain whose ID does not contain `devnet` or `local` MUST
> have `AllowSimulated = false` in both the `x/pouw` and `x/verify` module
> genesis parameters. CI enforces this via genesis linting.

---

## 3. Verification Modes

### 3.1 TEE (Trusted Execution Environment)

| Property | Requirement |
|----------|-------------|
| Supported platforms | `aws-nitro`, `intel-sgx`, `intel-tdx`, `amd-sev`, `arm-trustzone` |
| Minimum quote size | 64 bytes |
| User data binding | Quote `user_data` field MUST equal the output hash |
| Measurement | Must be present and non-empty; cross-checked against on-chain trusted measurements in `x/verify` keeper |
| Nonce | Required (freshness guarantee) |
| Timestamp freshness | Attestation must be < 10 minutes old at vote-extension validation time |
| Max quote age (keeper) | Configurable via `DefaultTeeQuoteMaxAge` param (default 24h) |

### 3.2 zkML (Zero-Knowledge Machine Learning)

| Property | Requirement |
|----------|-------------|
| Supported proof systems | `ezkl`, `risc0`, `plonky2`, `halo2` |
| Minimum proof size | 128 bytes |
| Verifying key hash | Must be exactly 32 bytes |
| Public inputs | Must be non-empty; binds model hash, input hash, and output commitment |
| Circuit hash | Present for registered circuits |
| Remote verification | Production: calls `ZkVerifierEndpoint` param; falls back to simulation only if `AllowSimulated=true` |

### 3.3 Hybrid (TEE + zkML)

Both TEE and zkML requirements above must be satisfied independently.

**Cross-validation rule** (enforced in `orchestrator.go`):
- When both TEE and zkML succeed, their output hashes MUST match.
- On mismatch, **both** results are marked failed (fail-closed).
- This is not a warning; it is a hard error.

---

## 4. Security Invariants

These invariants are non-negotiable across all environments:

### 4.1 Fail-Closed Verification

> If any verification step cannot produce a definitive positive result,
> the verification MUST fail.

Enforced at:
- **`orchestrator.go:verifyHybrid()`**: Output mismatch between TEE and zkML fails both.
- **`consensus.go:executeVerification()`**: No verifier + `AllowSimulated=false` returns error.
- **`keeper.go:VerifyZKMLProof()`**: No endpoint + `AllowSimulated=false` returns error.
- **`keeper.go:VerifyTEEAttestation()`**: No endpoint + `AllowSimulated=false` returns error.

### 4.2 No Phantom Jobs

> A vote extension claiming verification of job `J` is rejected if `J`
> does not exist on-chain.

Enforced at:
- **`consensus.go:VerifyVoteExtension()`**: Calls `keeper.GetJob(ctx, jobID)` for every successful verification.

### 4.3 Replay Protection

> Each vote extension verification must carry a unique 32-byte nonce.

Enforced at:
- **`consensus.go:validateVerificationWire()`**: Requires `len(nonce) == 32`.
- **`app/vote_extension.go`**: Nonce generated via `crypto/rand`.

### 4.4 Timing Side-Channel Protection

> All security-sensitive byte comparisons use constant-time operations.

Enforced at:
- **`orchestrator.go:bytesEqual()`**: Uses `crypto/subtle.ConstantTimeCompare`.

### 4.5 Hash Integrity

> Registered verifying keys and circuits always have their hashes
> recomputed from raw bytes. Caller-supplied hashes that don't match are
> rejected.

Enforced at:
- **`keeper.go:RegisterVerifyingKey()`**: Recomputes SHA-256 from `KeyBytes`, rejects mismatched caller hash.
- **`keeper.go:RegisterCircuit()`**: Recomputes SHA-256 from `CircuitBytes`, rejects mismatched caller hash.
- Duplicate registration is rejected (idempotency guard).

### 4.6 Domain-Separated Hashing

> All content hashes use domain-separation prefixes to prevent cross-type
> collisions.

Enforced at:
- **`app/vote_extension.go`**: `VoteExtension.ComputeHash()` uses length-prefixed encoding with domain separator.
- **`consensus.go:computeDeterministicOutput()`**: Uses `"aethelred_compute_v1"` suffix.

### 4.7 Consensus Threshold

> A computation result requires >= 67% validator agreement to finalize.

Enforced at:
- **`consensus.go:AggregateVoteExtensions()`**: `requiredVotes = (totalVotes * 67 / 100) + 1`.
- **`app/abci.go:PrepareProposal()`** and **`ProcessProposal()`**: Verify threshold before including seal transactions.

---

## 5. The `AllowSimulated` Dual-Flag System

Two independent boolean parameters gate simulated verification:

### 5.1 `x/pouw` Module (`x/pouw/types/genesis.go`)

```
Params.AllowSimulated = false (DEFAULT)
```

**Effect**: Controls whether `ConsensusHandler.executeVerification()` can
fall through to the simulated TEE/zkML/Hybrid code path when no real
`JobVerifier` is configured.

**When false**: Returns `"SECURITY: no verifier configured and
AllowSimulated=false"` and logs at ERROR level.

### 5.2 `x/verify` Module (`x/verify/types/genesis.go`)

```
Params.AllowSimulated = false (DEFAULT)
```

**Effect**: Controls whether `Keeper.VerifyZKMLProof()` and
`Keeper.VerifyTEEAttestation()` can fall back to simulated verification
when no remote verifier endpoint is configured.

**When false**: Returns error `"zk verifier endpoint not configured and
simulation disabled"`.

### 5.3 Production Rule

**Both flags MUST be `false` on mainnet and testnet.** There is no
legitimate reason to enable simulated verification in any network that
accepts real value or issues Digital Seals to external parties.

---

## 6. Vote Extension Validation Pipeline

```
Raw bytes from ABCI
    |
    v
[1] JSON unmarshal into VoteExtensionWire
    |
    v
[2] Version check (must == 1)
    |
    v
[3] Height check (must match current block)
    |
    v
[4] Timestamp check (not in the future by > 1 minute)
    |
    v
[5] For each VerificationWire:
    |-- [5a] Job ID present
    |-- [5b] Output hash == 32 bytes
    |-- [5c] Model hash == 32 bytes
    |-- [5d] Nonce == 32 bytes
    |-- [5e] Execution time > 0
    |-- [5f] Attestation type valid (tee | zkml | hybrid)
    |-- [5g] TEE: parse JSON, validate platform, measurement, quote >= 64B,
    |         user_data == output_hash, nonce present, timestamp < 10min
    |-- [5h] ZK: parse JSON, validate proof system, proof >= 128B,
    |         VK hash == 32B, public inputs present
    |-- [5i] Hybrid: both 5g and 5h
    |
    v
[6] Job existence check (successful verifications only)
    |
    v
ACCEPT or REJECT
```

---

## 7. Digital Seal Issuance Criteria

A Digital Seal is created only when ALL of the following hold:

1. A `ComputeJob` was submitted via a signed transaction with valid fee.
2. The job was assigned to validators via the scheduler.
3. Validators produced vote extensions with valid verification results.
4. >= 67% of voting validators agreed on the same output hash.
5. The block proposer aggregated the results and injected a seal transaction.
6. The `ProcessProposal` handler validated the seal transaction against the threshold.
7. The seal transaction was committed to state.

No seal is issued for:
- Jobs with fewer than `MinValidators` (default 3) participating.
- Jobs where the consensus threshold was not met.
- Jobs that expired (exceeded `JobTimeoutBlocks`).
- Verification results that use simulated verification in a non-simulated environment.

---

## 8. Incident Response

If a validator is discovered to have submitted forged attestations or
proofs:

1. **Immediate**: Slash the validator's stake by `SlashingPenalty` (default 10000 uaethel).
2. **Block-level**: Invalid vote extensions are rejected at `VerifyVoteExtension`, preventing the data from reaching consensus.
3. **Network-level**: Validators with consistently failed verifications have their reputation score degraded, reducing job assignment priority.

---

## 9. Audit & Compliance

- Every Digital Seal includes the full validator set that participated, their attestation types, and block height.
- Seals are queryable via gRPC: `GET /aethelred/seal/v1/seal/{id}`.
- Audit export available via `GET /aethelred/seal/v1/audit`.
- Regulatory compliance markers (`GDPR`, `HIPAA`) are stored per-seal for financial AI use cases.

---

## 10. Change Control

Changes to this policy require:
1. A governance proposal (when governance module is active).
2. Review by at least one security engineer.
3. Updated negative-case tests covering the changed invariant.
4. CI green on `./x/verify/...` and `./x/pouw/...`.

Note: some `x/verify/keeper` tests start local HTTP servers via `httptest`.
In sandboxed environments that block local sockets, those tests will be skipped
instead of failed.
