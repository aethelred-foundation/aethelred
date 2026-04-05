# Production / Development Gating Plan

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-02-05
**Owner**: Platform Lead

---

## 1. Overview

This document defines how the Aethelred network gates production-grade
verification from development/testing simulation. The gating system
ensures that simulated AI verification can never execute on production
networks, while preserving developer velocity on local and dev
environments.

---

## 2. Gating Architecture

```
                    ┌──────────────────────────────────────┐
                    │          Genesis Configuration        │
                    │                                       │
                    │  x/pouw params:                        │
                    │    AllowSimulated: false (default)    │
                    │                                       │
                    │  x/verify params:                     │
                    │    AllowSimulated: false (default)    │
                    │    ZkVerifierEndpoint: ""             │
                    │                                       │
                    └────────────┬─────────────────────────┘
                                 │
                    ┌────────────▼─────────────────────────┐
                    │         Runtime Checks                │
                    │                                       │
                    │  ConsensusHandler.executeVerification  │
                    │    ├─ verifier != nil? → USE IT       │
                    │    ├─ AllowSimulated? → SIMULATE      │
                    │    └─ else → REJECT (fail-closed)     │
                    │                                       │
                    │  Keeper.VerifyZKMLProof                │
                    │    ├─ ZkVerifierEndpoint? → CALL IT   │
                    │    ├─ AllowSimulated? → SIMULATE      │
                    │    └─ else → REJECT (fail-closed)     │
                    │                                       │
                    │  Keeper.VerifyTEEAttestation           │
                    │    ├─ AttestationEndpoint? → CALL IT  │
                    │    ├─ AllowSimulated? → SIMULATE      │
                    │    └─ else → REJECT (fail-closed)     │
                    └──────────────────────────────────────┘
```

---

## 3. Environment Matrix

### 3.1 Mainnet (`aethelred-mainnet-1`)

| Component | Configuration | Behavior |
|-----------|---------------|----------|
| `x/pouw AllowSimulated` | `false` | No simulated verification at consensus layer |
| `x/verify AllowSimulated` | `false` | No simulated proof/attestation verification |
| `ConsensusHandler.verifier` | **Must be set** | Real TEE/zkML verifier via `SetVerifier()` |
| `ZkVerifierEndpoint` | Production URL | Real EZKL verification service |
| TEE configs | Real measurements | Trusted enclave measurements from deployment |
| Genesis validation | CI-enforced | Lint rejects `AllowSimulated: true` |

### 3.2 Testnet (`aethelred-testnet-*`)

| Component | Configuration | Behavior |
|-----------|---------------|----------|
| `x/pouw AllowSimulated` | `false` | Same as mainnet |
| `x/verify AllowSimulated` | `false` | Same as mainnet |
| `ConsensusHandler.verifier` | **Must be set** | Staging verifier service |
| `ZkVerifierEndpoint` | Staging URL | Staging EZKL service |
| TEE configs | Staging measurements | Testnet enclave measurements |

### 3.3 Devnet (`aethelred-devnet-*`)

| Component | Configuration | Behavior |
|-----------|---------------|----------|
| `x/pouw AllowSimulated` | `true` (configurable) | Simulated verification allowed |
| `x/verify AllowSimulated` | `true` (configurable) | Simulated proof verification allowed |
| `ConsensusHandler.verifier` | Optional | Falls back to simulation |
| `ZkVerifierEndpoint` | Optional | Falls back to simulation |

### 3.4 Localnet (`aethelred-local-*`)

| Component | Configuration | Behavior |
|-----------|---------------|----------|
| `x/pouw AllowSimulated` | `true` | Always simulated |
| `x/verify AllowSimulated` | `true` | Always simulated |
| `ConsensusHandler.verifier` | Not set | Uses deterministic simulation |
| Single validator | Yes | No multi-validator consensus needed |

---

## 4. CI/CD Enforcement

### 4.1 Genesis Lint Rule

The CI pipeline includes a genesis lint step that validates:

```bash
# Pseudo-code for CI genesis validation
for genesis in deploy/config/genesis/*.json testnet/genesis.json; do
    # Extract AllowSimulated from both modules
    pouw_simulated=$(jq '.app_state.pouw.params.allow_simulated' "$genesis")
    verify_simulated=$(jq '.app_state.verify.params.allow_simulated' "$genesis")

    # Fail CI if either is true in non-dev configs
    if [[ "$genesis" != *"devnet"* && "$genesis" != *"local"* ]]; then
        if [[ "$pouw_simulated" == "true" || "$verify_simulated" == "true" ]]; then
            echo "FATAL: AllowSimulated=true in production genesis: $genesis"
            exit 1
        fi
    fi
done
```

### 4.2 Code-Level Guards

Each simulation code path is protected by a runtime check AND annotated
with a `WARNING` comment visible in code review:

```go
// WARNING: This function produces deterministic fake attestations.
// Production validators MUST use ConsensusHandler.SetVerifier() with a
// real JobVerifier that communicates with a TEE enclave.
// This code path is only reachable when AllowSimulated=true.
func (ch *ConsensusHandler) executeTEEVerification(...)
```

### 4.3 Test Coverage Requirements

| Path | Required Coverage |
|------|-------------------|
| `AllowSimulated=false` rejection | Negative test asserting error message |
| `AllowSimulated=true` simulation | Positive test asserting simulated output |
| Missing verifier + `false` | Negative test asserting fail-closed |
| Malformed TEE attestation | Negative test for each field |
| Malformed ZK proof | Negative test for each field |
| Output mismatch (hybrid) | Negative test asserting both fail |
| Phantom job vote | Negative test asserting rejection |
| Stale attestation | Negative test asserting >10min rejection |

Note: some `x/verify/keeper` tests start local HTTP servers via `httptest`.
In sandboxed environments that block local sockets, those tests will be skipped
instead of failed.

---

## 5. Validator Startup Checklist

Before a validator joins mainnet or testnet:

- [ ] `AllowSimulated` is `false` in both modules (from genesis).
- [ ] `ConsensusHandler.SetVerifier()` is called with a production `JobVerifier`.
- [ ] The `JobVerifier` connects to a real TEE enclave (AWS Nitro or equivalent).
- [ ] `ZkVerifierEndpoint` is set to the production EZKL verification service.
- [ ] `AttestationEndpoint` is set for each active TEE platform.
- [ ] Trusted measurements are configured in TEE configs for the correct enclave image.
- [ ] The validator's hardware meets requirements in `docs/validator/HARDWARE_REQUIREMENTS.md`.
- [ ] Node logs are monitored for any `SIMULATED verification` warnings (should never appear).

---

## 6. Governance Transitions

### 6.1 Enabling Simulation (Emergency Only)

In an emergency where all TEE/zkML infrastructure is unavailable,
governance can vote to temporarily enable `AllowSimulated`:

1. Submit `MsgUpdateParams` for both `x/pouw` and `x/verify`.
2. Requires supermajority (67%) governance vote.
3. All Digital Seals issued during the simulated window are marked with
   `SimulatedVerification: true` in their metadata.
4. A time-bound proposal (e.g., 24 hours) automatically reverts the flag.

### 6.2 Adding New Verification Methods

New TEE platforms or proof systems require:

1. Update `validPlatforms` or `validSystems` map in `consensus.go`.
2. Add the platform/system to `SupportedTeePlatforms` / `SupportedProofSystems` params.
3. Add structural validation in `validateTEEAttestationWire()` / `validateZKProofWire()`.
4. Negative test coverage for the new method.
5. Governance proposal to update on-chain params.

---

## 7. Monitoring & Alerting

| Alert | Trigger | Severity |
|-------|---------|----------|
| `simulated_verification` | Any log containing "SIMULATED verification" on non-dev chain | **P0 Critical** |
| `verification_blocked` | `executeVerification` returns SECURITY error | **P1 High** (verifier misconfiguration) |
| `attestation_stale` | TEE attestation rejected for staleness | **P2 Medium** |
| `output_mismatch` | Hybrid verification output mismatch | **P1 High** (potential byzantine behavior) |
| `phantom_job_vote` | Vote extension references unknown job | **P1 High** (potential attack) |
| `hash_integrity_violation` | RegisterVerifyingKey/RegisterCircuit hash mismatch | **P1 High** |

---

## 8. Migration Path: Dev to Production

```
Phase 1 (Localnet):
  AllowSimulated=true, no real verifier
  → Rapid iteration on consensus flow and seal creation

Phase 2 (Devnet):
  AllowSimulated=true, optional real verifier
  → Integrate real TEE enclave, test attestation flow
  → Integrate EZKL prover, test proof generation

Phase 3 (Testnet):
  AllowSimulated=false, real verifier required
  → Full production security policy
  → Multi-validator consensus testing
  → Negative-case test suite must pass

Phase 4 (Mainnet):
  AllowSimulated=false, real verifier required
  → Genesis lint enforced in CI
  → Monitoring alerts active
  → Audit trail enabled
```

---

## 9. Related Documents

- [Verification Policy](./VERIFICATION_POLICY.md) - Security invariants and validation rules
- [Hardware Requirements](../validator/HARDWARE_REQUIREMENTS.md) - Validator hardware specifications
- [Genesis Sprint](../hackathon/GENESIS_SPRINT.md) - Initial development plan
