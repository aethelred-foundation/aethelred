# SLO Definitions

Service Level Objectives for Aethelred mainnet operations. These targets apply to the production network and are validated via load testing, synthetic monitoring, and on-chain metrics.

## Block Production

| Metric | Target | Measurement |
|--------|--------|-------------|
| Block production availability | 99.9% | Percentage of expected block slots that produce a valid block over a 30-day rolling window. Missed blocks due to proposer downtime count against availability. |
| Block finalization time (p50) | <= 6s | Median time from block proposal to finalization (2/3+ validator commit). Measured via CometBFT consensus timestamps. |
| Block finalization time (p99) | <= 15s | 99th percentile block finalization latency. Exceeding this threshold triggers a P1 alert. |

## Job Processing (Proof-of-Useful-Work)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Job success rate | >= 99.0% | Percentage of submitted AI compute jobs that complete successfully (verified proof accepted on-chain) over a 24-hour rolling window. Failures include TEE attestation failures, proof verification failures, and timeout expiries. |

## RPC and API

| Metric | Target | Measurement |
|--------|--------|-------------|
| RPC availability | 99.95% | Percentage of time the public RPC endpoints (port 26657) and REST API (port 1317) return successful responses. Measured via synthetic health checks every 30 seconds from multiple geographic regions. |

## Bridge

| Metric | Target | Measurement |
|--------|--------|-------------|
| Bridge processing latency | < 15 minutes | Time from Ethereum transaction confirmation to corresponding Aethelred chain state update. Measured end-to-end including relayer pickup, proof generation, and on-chain verification. |

## Consensus Internals

| Metric | Target | Measurement |
|--------|--------|-------------|
| VRF verification latency (p99) | <= 50ms | 99th percentile time to verify a VRF proof during validator selection. Measured at the `x/pouw` module level. |
| Consensus round latency (p99) | <= 2500ms | 99th percentile time for a single CometBFT consensus round (propose + prevote + precommit). Excludes rounds that require >1 round due to proposer timeout. |

## Incident Response

| Severity | Response Target | Description |
|----------|----------------|-------------|
| P0 — Critical | < 5 minutes | Chain halt, consensus failure, active exploit, bridge fund loss. On-call engineer acknowledges and begins mitigation. |
| P1 — High | < 30 minutes | Degraded block production, elevated job failure rate (>5%), RPC availability below 99.5%, bridge delays >30 min. |
| P2 — Medium | < 4 hours | Non-critical performance degradation, single validator issues, non-blocking CI failures, documentation gaps. |

## SLO Burn Rate Alerts

To catch SLO violations early, the following burn-rate alerts are configured:

- **Fast burn (1h window)**: Alert if error budget consumption rate would exhaust the monthly budget within 1 day.
- **Slow burn (6h window)**: Alert if error budget consumption rate would exhaust the monthly budget within 3 days.

## Error Budget Policy

Each SLO has a monthly error budget derived from its target:

| SLO | Monthly Error Budget |
|-----|---------------------|
| Block production (99.9%) | ~43 minutes of downtime |
| RPC availability (99.95%) | ~22 minutes of downtime |
| Job success rate (99.0%) | 1% of total jobs may fail |

When the error budget is exhausted:
1. Feature deployments are frozen until the budget resets.
2. Engineering effort shifts to reliability work.
3. A post-incident review is conducted if a single incident consumed >50% of the budget.

## Validation

These SLOs are validated through:
- **Load testing**: `make loadtest` and `make loadtest-scenarios` (see `loadtest-results/BENCHMARK_TOPOLOGY.md`)
- **Synthetic monitoring**: Automated health checks against testnet and mainnet endpoints
- **On-chain metrics**: Block explorer and Prometheus/Grafana dashboards
- **Incident tracking**: PagerDuty integration with escalation policies matching the response targets above
