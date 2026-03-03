# Protocol Monitoring & Alerting

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-02-28
**Owner**: SRE / Security Engineering

---

## 1. Overview

This document defines the monitoring, alerting, and observability requirements
for the Aethelred Protocol across all layers: consensus, bridge, contracts,
and infrastructure.

---

## 2. Metrics Architecture

```
┌────────────────┐    ┌──────────────┐    ┌──────────────┐
│  Aethelred Node│───>│  Prometheus  │───>│   Grafana    │
│  (Go + Rust)   │    │  (scraper)   │    │  (dashboards)│
└────────────────┘    └──────────────┘    └──────────────┘
                             │
┌────────────────┐           │             ┌──────────────┐
│  Bridge Relayer│───────────┘        ┌───>│  PagerDuty   │
│  (Rust)        │                    │    │  (oncall)    │
└────────────────┘           ┌────────┤    └──────────────┘
                             │        │
┌────────────────┐    ┌──────▼─────┐  │    ┌──────────────┐
│  EVM Contracts │───>│ AlertManager│──┴───>│  Slack       │
│  (events/logs) │    │            │       │  (channels)  │
└────────────────┘    └────────────┘       └──────────────┘
```

---

## 3. Consensus Metrics

### 3.1 Block Production

| Metric | Type | Alert Threshold | Severity |
|--------|------|-----------------|----------|
| `cometbft_consensus_height` | Gauge | No increase in 30s | P0 Critical |
| `cometbft_consensus_rounds` | Counter | > 3 rounds for single height | P1 High |
| `cometbft_consensus_validators` | Gauge | < 2/3 of expected set | P0 Critical |
| `cometbft_consensus_missing_validators` | Gauge | > 1/3 of set missing | P0 Critical |
| `cometbft_consensus_block_time_seconds` | Histogram | p99 > 15s (2.5x target) | P1 High |

### 3.2 VRF Leader Election

| Metric | Type | Alert Threshold | Severity |
|--------|------|-----------------|----------|
| `aethelred_vrf_prove_duration_ms` | Histogram | p99 > 100ms | P2 Medium |
| `aethelred_vrf_verify_duration_ms` | Histogram | p99 > 50ms | P2 Medium |
| `aethelred_vrf_verification_failures` | Counter | > 5 in 10 minutes | P1 High |
| `aethelred_vrf_leader_elections` | Counter | Monotonic (no resets) | P2 Medium |

### 3.3 AI Verification

| Metric | Type | Alert Threshold | Severity |
|--------|------|-----------------|----------|
| `aethelred_verification_success_total` | Counter | Rate drops > 50% | P1 High |
| `aethelred_verification_failure_total` | Counter | Any increase on prod | P1 High |
| `aethelred_simulated_verification_total` | Counter | Any on non-dev chain | P0 Critical |
| `aethelred_attestation_age_seconds` | Gauge | > 600 (10 min) | P2 Medium |
| `aethelred_digital_seals_issued` | Counter | Monotonic tracking | Informational |

---

## 4. Bridge Metrics

| Metric | Type | Alert Threshold | Severity |
|--------|------|-----------------|----------|
| `aethelred_bridge_eth_deposits_total` | Counter | Monotonic | Info |
| `aethelred_bridge_eth_withdrawals_total` | Counter | Monotonic | Info |
| `aethelred_bridge_aethelred_mints_total` | Counter | Monotonic | Info |
| `aethelred_bridge_pending_deposits` | Gauge | > 100 pending | P2 Medium |
| `aethelred_bridge_pending_withdrawals` | Gauge | > 50 pending | P2 Medium |
| `aethelred_bridge_reorg_events` | Counter | Any occurrence | P1 High |
| `aethelred_bridge_rate_limit_utilization` | Gauge | > 80% | P2 Medium |
| `aethelred_bridge_rate_limit_exceeded` | Counter | Any occurrence | P1 High |
| `aethelred_bridge_confirmation_depth` | Gauge | < 64 | P0 Critical |

---

## 5. Smart Contract Monitoring

### 5.1 Event-Based Monitoring

Monitor these on-chain events via event indexer (e.g., The Graph, custom):

| Event | Contract | Alert Condition | Severity |
|-------|----------|-----------------|----------|
| `KeyRotationQueued` | GovernanceTimelock | Any occurrence | P1 High |
| `KeyRotationExecuted` | GovernanceTimelock | Verify authorized | P1 High |
| `EmergencyPaused` | CircuitBreaker | Any occurrence | P0 Critical |
| `ComplianceSlash` | Token | Any occurrence | P1 High |
| `BlacklistStatusChanged` | Token | Unexpected addresses | P2 Medium |
| `RateLimitExceeded` | Bridge | Any occurrence | P1 High |
| `ScheduleRevoked` | Vesting | Any occurrence | P2 Medium |

### 5.2 State Monitoring

Poll these contract state values periodically (every block or every minute):

| Check | Expected | Alert | Severity |
|-------|----------|-------|----------|
| `totalSupply()` | 10,000,000,000 * 1e18 | Any deviation | P0 Critical |
| `paused()` | false (normally) | true on mainnet | P0 Critical |
| `getMinDelay()` | >= 7 days (604800) | < 7 days | P0 Critical |
| `currentWindowMinted / maxMintPerWindow` | < 80% | > 80% | P2 Medium |

---

## 6. Infrastructure Metrics

| Metric | Type | Alert Threshold | Severity |
|--------|------|-----------------|----------|
| Node disk usage | Gauge | > 80% | P2 Medium |
| Node memory usage | Gauge | > 90% | P1 High |
| Node CPU usage | Gauge | > 80% sustained 5m | P2 Medium |
| P2P peer count | Gauge | < 3 peers | P1 High |
| RPC latency p99 | Histogram | > 500ms | P2 Medium |
| TLS certificate expiry | Gauge | < 30 days | P2 Medium |
| Database size growth rate | Rate | > 10GB/day | P2 Medium |

---

## 7. Grafana Dashboards

### 7.1 Required Dashboards

| Dashboard | Audience | Key Panels |
|-----------|----------|------------|
| **Consensus Overview** | SRE | Block height, rounds, validators, VRF stats |
| **Bridge Operations** | SRE + Ops | Deposits, withdrawals, rate limits, reorgs |
| **Token Economics** | Business + Ops | Supply, circulation, vesting progress |
| **Security Posture** | Security | Failures, anomalies, attestation health |
| **Infrastructure** | SRE | CPU, memory, disk, network, peers |

### 7.2 Example Prometheus Rules

```yaml
# prometheus/rules/aethelred.yml
groups:
  - name: aethelred_consensus
    rules:
      - alert: ConsensusHalted
        expr: increase(cometbft_consensus_height[1m]) == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "Consensus has halted - no new blocks in 30s"

      - alert: VRFVerificationSpike
        expr: rate(aethelred_vrf_verification_failures[10m]) > 0.05
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "VRF verification failure rate exceeds 5%"

  - name: aethelred_bridge
    rules:
      - alert: BridgeReorgDetected
        expr: increase(aethelred_bridge_reorg_events[5m]) > 0
        labels:
          severity: high
        annotations:
          summary: "Ethereum reorg detected affecting bridge deposits"

      - alert: RateLimitNearCapacity
        expr: aethelred_bridge_rate_limit_utilization > 0.8
        for: 5m
        labels:
          severity: medium
        annotations:
          summary: "Bridge rate limit at >80% capacity"

  - name: aethelred_security
    rules:
      - alert: SimulatedVerificationOnProd
        expr: increase(aethelred_simulated_verification_total[1m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "CRITICAL: Simulated verification detected on production chain"

      - alert: TokenSupplyAnomaly
        expr: aethelred_token_total_supply != 1e28
        labels:
          severity: critical
        annotations:
          summary: "Token total supply deviates from expected value"
```

---

## 8. Log Aggregation

### 8.1 Structured Logging Requirements

All components must use structured logging with these fields:

| Field | Type | Required | Example |
|-------|------|----------|---------|
| `level` | string | Yes | `info`, `warn`, `error` |
| `component` | string | Yes | `consensus`, `bridge`, `vrf` |
| `msg` | string | Yes | Human-readable message |
| `block_height` | uint64 | When available | `123456` |
| `tx_hash` | hex string | When available | `0xabc...` |
| `error` | string | On error | Error details |
| `duration_ms` | float64 | For operations | `42.5` |

### 8.2 Security-Sensitive Log Redaction

The following must **never** appear in logs:
- Private keys, mnemonics, seeds
- Full transaction data for compliance operations
- PII (use hashed identifiers)
- Internal IP addresses in public-facing logs

---

## 9. SLA Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Block production uptime | 99.9% | Blocks produced / expected blocks |
| Bridge processing latency | < 15 minutes (ETH->AETHEL) | Deposit to mint time |
| RPC availability | 99.95% | Successful RPC responses |
| Alert response time (P0) | < 5 minutes | PagerDuty acknowledgement |
| Alert response time (P1) | < 30 minutes | PagerDuty acknowledgement |
| Mean time to resolution (P0) | < 1 hour | Incident ticket duration |
