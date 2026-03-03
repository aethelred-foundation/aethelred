# Decentralization Roadmap

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-02-28
**Owner**: Protocol Engineering / Governance

---

## 1. Overview

This document outlines the progressive decentralization plan for the Aethelred
Protocol, transitioning from a foundation-operated network to a fully
community-governed, permissionless blockchain.

---

## 2. Current State (Pre-Mainnet)

### 2.1 Centralization Points

| Component | Current State | Risk | Decentralization Plan |
|-----------|---------------|------|-----------------------|
| **Validator set** | Foundation-operated genesis validators | Single operator | Progressive onboarding |
| **Bridge guardian** | Single foundation-controlled key | Single point of compromise | Multi-sig, then DAO |
| **Governance keys** | 3 foundation keys (Issuer, Foundation, Auditor) | Foundation control | Timelock + multi-sig + DAO |
| **Token distribution** | Foundation holds majority via vesting | Concentration risk | 48-month vesting with cliff |
| **Upgrade authority** | Foundation-controlled UUPS proxy admin | Unilateral upgrades | Timelock + governance vote |
| **TEE measurements** | Foundation registers trusted measurements | Trust assumption | On-chain registry with governance |
| **RPC infrastructure** | Foundation-operated nodes | Availability | Community node incentives |
| **Code repository** | Foundation-controlled GitHub | Supply chain | Multi-sig releases, reproducible builds |

### 2.2 Existing Decentralization Controls

- **7-day governance timelock**: Key rotations require 7-day delay
- **Dual-signature requirement**: Key rotation needs both Issuer + Foundation signatures
- **AdminMustBeContract**: No EOA admins allowed on mainnet
- **UUPS proxy**: Upgrade requires `_authorizeUpgrade()` role check
- **Circuit breaker**: Emergency pause bounded to 24h-14d window

---

## 3. Decentralization Phases

### Phase 1: Foundation Launch (Months 0-6)

**Goal**: Secure, stable launch with foundation oversight.

| Action | Timeline | Details |
|--------|----------|---------|
| Genesis with 7-21 foundation validators | Month 0 | Geographically distributed |
| Bridge with single guardian + rate limits | Month 0 | 200 ETH/day max mint |
| 7-day governance timelock active | Month 0 | All key rotations timelocked |
| Vesting contracts deployed and locked | Month 0 | 48-month vesting, 6-month cliff |
| Bug bounty program launched | Month 1 | Up to $500K for critical bugs |
| First external audit completed | Month 2 | Tier-1 auditor engagement |

**Exit Criteria**:
- [ ] 3 months of stable block production
- [ ] No critical security incidents
- [ ] External audit with no unresolved critical findings
- [ ] Community validator applications open

### Phase 2: Validator Expansion (Months 6-12)

**Goal**: Expand validator set to include community operators.

| Action | Timeline | Details |
|--------|----------|---------|
| Open validator onboarding (permissioned) | Month 6 | Application + KYC process |
| 21 -> 50 validator expansion | Month 6-9 | Progressive stake delegation |
| Validator performance monitoring | Month 6+ | Public dashboard |
| Slashing parameters activated | Month 7 | Double-sign, downtime slashing |
| Delegation / staking opens to public | Month 8 | Token holders can delegate |
| Foundation reduces to < 50% of stake | Month 12 | Via delegation and new validators |

**Exit Criteria**:
- [ ] >= 50 independent validators
- [ ] Foundation controls < 50% of total stake
- [ ] No single entity controls > 20% of stake
- [ ] Nakamoto coefficient >= 7

### Phase 3: Governance Transition (Months 12-18)

**Goal**: Transfer governance authority from foundation to token holders.

| Action | Timeline | Details |
|--------|----------|---------|
| On-chain governance module activated | Month 12 | Cosmos SDK `x/gov` |
| Parameter changes via governance vote | Month 12 | 67% supermajority required |
| Bridge guardian upgraded to 3-of-5 multi-sig | Month 13 | Include community signers |
| Software upgrades via governance proposal | Month 14 | Validator vote required |
| Foundation governance key shared with DAO | Month 15 | Multi-sig with DAO representatives |
| Community grants program (on-chain treasury) | Month 16 | DAO-controlled spending |
| Emergency pause authority shared with DAO | Month 18 | Multi-sig: 2 foundation + 3 community |

**Exit Criteria**:
- [ ] Governance module active with > 30% participation rate
- [ ] >= 3 successful governance proposals executed
- [ ] Bridge guardian includes community signers
- [ ] Emergency actions require community approval

### Phase 4: Full Decentralization (Months 18-36)

**Goal**: Foundation becomes one of many participants, not a privileged operator.

| Action | Timeline | Details |
|--------|----------|---------|
| Foundation reduces to 1 of N governance signers | Month 18 | No veto power |
| Permissionless validator joining | Month 20 | Remove application requirement |
| Bridge guardian: 5-of-9 with community majority | Month 22 | Foundation holds 2 of 9 keys |
| Upgrade authority: governance-only (no admin key) | Month 24 | Timelock + vote only |
| TEE measurement registry: governance-controlled | Month 24 | No foundation-only updates |
| Foundation stake < 20% of total | Month 30 | Natural dilution via rewards |
| Full DAO control of treasury | Month 36 | Foundation advisory role only |

**Exit Criteria**:
- [ ] Nakamoto coefficient >= 15
- [ ] Foundation controls < 20% of stake
- [ ] No single key can halt the network
- [ ] All parameter changes require governance vote

---

## 4. Decentralization Metrics

### 4.1 Key Metrics to Track

| Metric | Phase 1 Target | Phase 4 Target | Measurement |
|--------|----------------|----------------|-------------|
| **Nakamoto coefficient** | >= 3 | >= 15 | Min validators to halt consensus |
| **Validator count** | 7-21 | 100+ | Active validator set size |
| **Stake distribution HHI** | < 0.3 | < 0.05 | Herfindahl-Hirschman Index |
| **Foundation stake %** | 100% | < 20% | Foundation-controlled stake |
| **Geographic distribution** | 3+ countries | 20+ countries | Validator locations |
| **Client diversity** | 1 client | 2+ clients | Independent implementations |
| **Governance participation** | N/A | > 30% | Token-weighted vote participation |
| **Bridge signer diversity** | 1 (foundation) | 9 (5+ community) | Independent signers |

### 4.2 Dashboard

A public decentralization dashboard will be maintained at:
`https://dashboard.aethelred.io/decentralization`

Showing real-time:
- Validator map (geographic distribution)
- Stake distribution chart (Lorenz curve)
- Nakamoto coefficient over time
- Governance participation rate
- Bridge signer status

---

## 5. Client Diversity Plan

### 5.1 Phase 1: Reference Client

- Single Go implementation (Cosmos SDK based)
- All consensus, state machine, and verification logic

### 5.2 Phase 2: Alternative Client (Months 12-24)

- Fund development of a second client implementation
- Options: Rust (via Tendermint ABCI), or fork of CometBFT with alternative runtime
- Specification document for consensus and state transition rules
- Cross-client test suite for compatibility

### 5.3 Phase 3: Ecosystem Clients (Months 24+)

- Open specification for third-party implementations
- Compliance test suite (like Ethereum's Hive tests)
- Client diversity monitoring and incentive programs

---

## 6. Governance Framework

### 6.1 Proposal Types

| Type | Quorum | Threshold | Timelock | Example |
|------|--------|-----------|----------|---------|
| **Text/Signal** | 20% | 50% | None | Community sentiment |
| **Parameter Change** | 33% | 67% | 48h | Rate limit adjustment |
| **Software Upgrade** | 40% | 67% | 7 days | Binary upgrade |
| **Treasury Spend** | 33% | 67% | 48h | Grant funding |
| **Emergency Action** | 50% | 75% | 24h | Security response |
| **Constitutional** | 50% | 80% | 14 days | Governance rule change |

### 6.2 Governance Security

- **Timelock on all actions**: Minimum 24h for parameter changes, 7 days for upgrades
- **Veto power**: Foundation retains veto during Phase 1-2 only (sunset at Phase 3)
- **Emergency guardian**: Multi-sig can pause for up to 14 days without governance vote
- **No retroactive changes**: Governance cannot modify past state or reverse finalized blocks

---

## 7. Risk Mitigation

### 7.1 Risks of Premature Decentralization

| Risk | Mitigation |
|------|-----------|
| Governance attack (vote buying) | Quadratic voting or conviction voting consideration |
| Low participation leading to minority control | Quorum requirements, delegation incentives |
| Malicious validator cartel | Slashing, stake caps, geographic diversity requirements |
| Bridge guardian key compromise | Progressive multi-sig expansion, hardware security |
| Hostile governance proposal | Timelock + veto (Phase 1-2), constitutional constraints |

### 7.2 Risks of Delayed Decentralization

| Risk | Mitigation |
|------|-----------|
| Foundation key compromise = total loss | Aggressive timeline for multi-sig expansion |
| Regulatory single point of failure | Legal entity diversification |
| Community trust erosion | Transparent roadmap with public metrics |
| Censorship concerns | Public commitment to timeline with financial penalties |

---

## 8. Commitments

The Aethelred Foundation commits to:

1. **No unilateral action after Phase 3**: All protocol changes require governance vote
2. **Transparent stake reporting**: Monthly disclosure of foundation-controlled stake
3. **Open validator set by Month 20**: Permissionless joining with only minimum stake requirement
4. **Client specification by Month 18**: Enable alternative implementations
5. **Bug bounty continuity**: Maintain bug bounty program regardless of governance transition
6. **Decentralization dashboard**: Public, real-time metrics on all decentralization KPIs
