# Aethelred Performance Baselines

## Production Performance Requirements and Benchmarks

**Version:** 1.0.0
**Classification:** Operations
**Last Updated:** 2024

---

## Executive Summary

This document defines the performance baselines for Aethelred blockchain operations. These baselines are derived from extensive benchmarking and represent the minimum acceptable performance for production deployments.

---

## Table of Contents

1. [Overview](#overview)
2. [Core Benchmark Baselines](#core-benchmark-baselines)
3. [Module-Specific Baselines](#module-specific-baselines)
4. [Hardware Requirements](#hardware-requirements)
5. [Monitoring and Alerting](#monitoring-and-alerting)
6. [Performance Tuning](#performance-tuning)
7. [Benchmark Methodology](#benchmark-methodology)

---

## Overview

### Performance Philosophy

Aethelred is designed for institutional-grade AI verification workloads. Performance baselines ensure:

- **Deterministic Consensus**: All validators must process blocks within acceptable timeframes
- **Low Latency Verification**: zkML and TEE verification must complete within block time
- **Scalability**: System must handle increasing job volumes without degradation
- **Predictability**: Performance must be consistent and measurable

### Baseline Categories

| Category | Description | Criticality |
|----------|-------------|-------------|
| Consensus | Block production and voting | Critical |
| Verification | zkML and TEE proof verification | Critical |
| State | State transitions and queries | High |
| Network | P2P and RPC operations | High |
| Storage | Database and caching | Medium |

---

## Core Benchmark Baselines

### Invariant Checks (AllInvariants)

The `AllInvariants` benchmark measures the time to perform a complete end-to-end invariant scan of the blockchain state.

```yaml
AllInvariants:
  description: "End-to-end invariant scan"
  max_avg_time: 10ms
  max_p95_time: 25ms
  max_p99_time: 50ms
  min_ops_per_sec: 100

  conditions:
    - "Must complete within block time"
    - "No false positives allowed"
    - "State consistency guaranteed"

  failure_impact: "Consensus halt if invariants fail"
```

**Why These Numbers:**
- 10ms average allows invariant checks during EndBlock
- 50ms P99 provides headroom for complex state
- 100 ops/sec supports 6-second block times with margin

### Parameter Validation (ValidateParams)

The `ValidateParams` benchmark measures module parameter validation performance.

```yaml
ValidateParams:
  description: "Parameter validation"
  max_avg_time: 200µs
  max_p95_time: 500µs
  max_p99_time: 1ms
  min_ops_per_sec: 100000

  conditions:
    - "Called on every transaction"
    - "Must not block consensus"
    - "Zero memory allocations preferred"

  failure_impact: "Transaction rejection latency increase"
```

**Why These Numbers:**
- 200µs average supports high transaction throughput
- 100K ops/sec handles peak mainnet load

### EndBlock Consistency Checks

```yaml
EndBlockConsistencyChecks:
  description: "EndBlock consistency checks"
  max_avg_time: 10ms
  max_p95_time: 25ms
  max_p99_time: 50ms
  min_ops_per_sec: 100

  conditions:
    - "Executed every block"
    - "Must complete before block finalization"
    - "Includes job expiration, validator updates"

  failure_impact: "Block production delay"
```

### Validator Performance Scoring

```yaml
PerformanceScore:
  description: "Validator performance scoring"
  max_avg_time: 50µs
  max_p95_time: 100µs
  max_p99_time: 200µs
  min_ops_per_sec: 1000000

  conditions:
    - "Called during reward distribution"
    - "Per-validator computation"
    - "Deterministic across all nodes"

  failure_impact: "Reward calculation delay"
```

---

## Module-Specific Baselines

### PoUW Module (Proof-of-Useful-Work)

```yaml
pouw_module:
  job_submission:
    description: "Submit compute job transaction"
    max_avg_time: 5ms
    max_p95_time: 15ms
    max_p99_time: 30ms

  job_completion:
    description: "Complete job and create seal"
    max_avg_time: 20ms
    max_p95_time: 50ms
    max_p99_time: 100ms

  job_query:
    description: "Query job by ID"
    max_avg_time: 500µs
    max_p95_time: 2ms
    max_p99_time: 5ms

  pending_jobs_list:
    description: "List pending jobs"
    max_avg_time: 10ms
    max_p95_time: 30ms
    max_p99_time: 100ms
    note: "Scales with pending job count"
```

### Verify Module (ZK and TEE Verification)

```yaml
verify_module:
  zk_proof_verification:
    description: "Verify zkML proof (Groth16)"
    max_avg_time: 50ms
    max_p95_time: 100ms
    max_p99_time: 200ms
    note: "Proof system dependent"

    by_system:
      groth16:
        max_time: 50ms
      plonk:
        max_time: 75ms
      halo2:
        max_time: 100ms
      ezkl:
        max_time: 150ms

  tee_attestation_verification:
    description: "Verify TEE attestation"
    max_avg_time: 30ms
    max_p95_time: 75ms
    max_p99_time: 150ms

    by_platform:
      intel_sgx_dcap:
        max_time: 40ms
      amd_sev_snp:
        max_time: 35ms
      aws_nitro:
        max_time: 30ms

  verifying_key_registration:
    description: "Register new verifying key"
    max_avg_time: 5ms
    max_p95_time: 15ms
    max_p99_time: 30ms
```

### Seal Module (Digital Seals)

```yaml
seal_module:
  seal_creation:
    description: "Create digital seal"
    max_avg_time: 10ms
    max_p95_time: 25ms
    max_p99_time: 50ms

  seal_verification:
    description: "Verify seal integrity"
    max_avg_time: 5ms
    max_p95_time: 15ms
    max_p99_time: 30ms

  seal_query:
    description: "Query seal by ID"
    max_avg_time: 500µs
    max_p95_time: 2ms
    max_p99_time: 5ms

  seal_revocation:
    description: "Revoke digital seal"
    max_avg_time: 5ms
    max_p95_time: 15ms
    max_p99_time: 30ms
```

### Consensus Operations

```yaml
consensus:
  vote_extension:
    description: "ExtendVote ABCI++ handler"
    max_avg_time: 50ms
    max_p95_time: 100ms
    max_p99_time: 200ms
    note: "Includes verification result aggregation"

  verify_vote_extension:
    description: "VerifyVoteExtension handler"
    max_avg_time: 10ms
    max_p95_time: 25ms
    max_p99_time: 50ms

  prepare_proposal:
    description: "PrepareProposal handler"
    max_avg_time: 100ms
    max_p95_time: 200ms
    max_p99_time: 500ms
    note: "Scales with transaction count"

  process_proposal:
    description: "ProcessProposal handler"
    max_avg_time: 100ms
    max_p95_time: 200ms
    max_p99_time: 500ms
```

---

## Hardware Requirements

### Minimum Production Requirements

```yaml
minimum_requirements:
  cpu:
    cores: 8
    threads: 16
    frequency: "3.0 GHz base"
    architecture: "x86_64 with AVX2"
    note: "ARM64 supported with reduced performance"

  memory:
    ram: 32GB
    type: "DDR4-3200 or better"
    ecc: "Recommended for validators"

  storage:
    type: "NVMe SSD"
    capacity: 1TB
    iops_read: 100000
    iops_write: 50000
    latency: "<100µs P99"

  network:
    bandwidth: "1 Gbps"
    latency: "<50ms to peers"

  tee: # If running TEE verification
    intel_sgx: "SGX2 with 128GB EPC"
    # OR
    amd_sev: "SEV-SNP capable"
```

### Recommended Production Requirements

```yaml
recommended_requirements:
  cpu:
    cores: 32
    threads: 64
    frequency: "3.5 GHz base"
    note: "AMD EPYC or Intel Xeon Scalable"

  memory:
    ram: 128GB
    type: "DDR5-4800"
    ecc: "Required"

  storage:
    type: "NVMe SSD (Enterprise)"
    capacity: 4TB
    iops_read: 500000
    iops_write: 200000
    note: "Consider RAID-1 for reliability"

  network:
    bandwidth: "10 Gbps"
    latency: "<10ms to peers"
    redundancy: "Dual NICs recommended"

  tee:
    intel_sgx: "SGX2 with 512GB EPC"
    gpu: "NVIDIA H100 with CC support"
```

### Cloud Instance Recommendations

| Provider | Instance Type | vCPUs | RAM | Notes |
|----------|---------------|-------|-----|-------|
| AWS | c6i.8xlarge | 32 | 64GB | Compute optimized |
| AWS | c6a.8xlarge | 32 | 64GB | AMD-based alternative |
| GCP | c2-standard-30 | 30 | 120GB | Compute optimized |
| Azure | Standard_F32s_v2 | 32 | 64GB | Compute optimized |

---

## Monitoring and Alerting

### Key Metrics to Monitor

```yaml
metrics:
  # Latency metrics
  latency:
    - name: aethelred_tx_processing_time_seconds
      description: "Transaction processing latency"
      buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1]

    - name: aethelred_verification_time_seconds
      description: "Verification operation latency"
      labels: [type, platform]

    - name: aethelred_consensus_round_time_seconds
      description: "Consensus round duration"

  # Throughput metrics
  throughput:
    - name: aethelred_jobs_submitted_total
      description: "Total compute jobs submitted"

    - name: aethelred_seals_created_total
      description: "Total digital seals created"

    - name: aethelred_verifications_total
      description: "Total verifications performed"
      labels: [type, result]

  # Resource metrics
  resources:
    - name: aethelred_pending_jobs_count
      description: "Current pending job queue size"

    - name: aethelred_validator_online_count
      description: "Online validators count"
```

### Alert Thresholds

```yaml
alerts:
  critical:
    - name: HighTransactionLatency
      condition: "aethelred_tx_processing_time_seconds > 1.0"
      duration: 5m
      action: "Page on-call immediately"

    - name: ConsensusTimeout
      condition: "aethelred_consensus_round_time_seconds > 10"
      duration: 1m
      action: "Page on-call immediately"

    - name: VerificationBacklog
      condition: "aethelred_pending_jobs_count > 10000"
      duration: 10m
      action: "Page on-call"

  warning:
    - name: ElevatedLatency
      condition: "aethelred_tx_processing_time_seconds > 0.5"
      duration: 15m
      action: "Notify via Slack"

    - name: LowValidatorCount
      condition: "aethelred_validator_online_count < 67"
      duration: 5m
      action: "Notify via Slack"
```

### Grafana Dashboard Panels

```json
{
  "dashboard": {
    "title": "Aethelred Performance Baselines",
    "panels": [
      {
        "title": "Transaction Processing Latency",
        "type": "timeseries",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, rate(aethelred_tx_processing_time_seconds_bucket[5m]))",
            "legendFormat": "P99"
          },
          {
            "expr": "histogram_quantile(0.95, rate(aethelred_tx_processing_time_seconds_bucket[5m]))",
            "legendFormat": "P95"
          }
        ],
        "thresholds": [
          {"value": 0.05, "color": "green"},
          {"value": 0.1, "color": "yellow"},
          {"value": 0.5, "color": "red"}
        ]
      },
      {
        "title": "Verification Throughput",
        "type": "timeseries",
        "targets": [
          {
            "expr": "sum(rate(aethelred_verifications_total[5m]))",
            "legendFormat": "Verifications/sec"
          }
        ]
      },
      {
        "title": "Baseline Compliance",
        "type": "gauge",
        "targets": [
          {
            "expr": "(aethelred_baseline_checks_passed / aethelred_baseline_checks_total) * 100",
            "legendFormat": "Compliance %"
          }
        ],
        "thresholds": [
          {"value": 95, "color": "red"},
          {"value": 99, "color": "yellow"},
          {"value": 100, "color": "green"}
        ]
      }
    ]
  }
}
```

---

## Performance Tuning

### Go Runtime Tuning

```bash
# Recommended environment variables for validators
export GOGC=100                    # GC target percentage
export GOMEMLIMIT=28GiB           # Soft memory limit
export GOMAXPROCS=16              # Match physical cores
export GODEBUG=gctrace=0          # Disable GC tracing in production
```

### CometBFT Configuration

```toml
# config.toml optimizations

[mempool]
size = 10000
max_txs_bytes = 1073741824  # 1GB
cache_size = 10000

[consensus]
timeout_propose = "3s"
timeout_propose_delta = "500ms"
timeout_prevote = "1s"
timeout_prevote_delta = "500ms"
timeout_precommit = "1s"
timeout_precommit_delta = "500ms"
timeout_commit = "5s"

[p2p]
max_num_inbound_peers = 40
max_num_outbound_peers = 10
flush_throttle_timeout = "100ms"
max_packet_msg_payload_size = 1024

[statesync]
enable = true
rpc_servers = "node1:26657,node2:26657"
trust_height = 1000
trust_hash = ""
```

### Database Tuning (LevelDB/RocksDB)

```yaml
# app.toml database settings
[database]
# Use RocksDB for production
backend = "rocksdb"

[rocksdb]
# Optimize for SSDs
block_size = 32768
cache_size = 8589934592  # 8GB
write_buffer_size = 134217728  # 128MB
max_write_buffer_number = 4
target_file_size_base = 67108864  # 64MB
max_open_files = 10000
compression = "lz4"
```

---

## Benchmark Methodology

### Running Benchmarks

```bash
# Run all performance benchmarks
go test -bench=. -benchmem -benchtime=10s ./x/pouw/keeper/...

# Run specific baseline tests
go test -v -run TestDefaultBenchmarkBaselines ./x/pouw/keeper/

# Generate benchmark report
go test -bench=. -benchmem -json ./... > benchmark-results.json

# Compare against baselines
aethelred benchmark evaluate --results benchmark-results.json
```

### Benchmark Environment

```yaml
benchmark_environment:
  isolation:
    - "Dedicated benchmark machines"
    - "No other workloads running"
    - "Stable network conditions"

  warmup:
    - "5 minute warmup period"
    - "Discard first 1000 operations"

  duration:
    - "Minimum 10 seconds per benchmark"
    - "At least 10,000 operations"

  repetition:
    - "Run 5 times minimum"
    - "Report median results"

  reporting:
    - "Include hardware specifications"
    - "Include Go/Rust versions"
    - "Include commit hash"
```

### Baseline Violation Policy

```yaml
violation_policy:
  severity_levels:
    critical:
      threshold: ">2x baseline"
      action: "Block release"

    warning:
      threshold: ">1.5x baseline"
      action: "Require justification"

    notice:
      threshold: ">1.2x baseline"
      action: "Track in metrics"

  exceptions:
    - "New features may have temporary regressions"
    - "Security fixes take priority over performance"
    - "Document all exceptions in release notes"
```

---

## Appendix: Baseline Summary Table

| Benchmark | Max Avg | Max P95 | Max P99 | Min Ops/Sec |
|-----------|---------|---------|---------|-------------|
| AllInvariants | 10ms | 25ms | 50ms | 100 |
| ValidateParams | 200µs | 500µs | 1ms | 100,000 |
| EndBlockConsistencyChecks | 10ms | 25ms | 50ms | 100 |
| PerformanceScore | 50µs | 100µs | 200µs | 1,000,000 |
| JobSubmission | 5ms | 15ms | 30ms | 200 |
| JobCompletion | 20ms | 50ms | 100ms | 50 |
| ZKProofVerification | 50ms | 100ms | 200ms | 20 |
| TEEAttestation | 30ms | 75ms | 150ms | 30 |
| SealCreation | 10ms | 25ms | 50ms | 100 |
| VoteExtension | 50ms | 100ms | 200ms | 20 |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial release |

---

*This document is part of the Aethelred Operations Documentation.*
