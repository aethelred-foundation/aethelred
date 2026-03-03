# Performance Baselines

**Purpose:** define repeatable benchmark runs and baseline thresholds for performance regressions.

---

## 1. How to Run Benchmarks

1. Run core Go benchmarks:

```bash
make bench
```

2. Run benchmarks and capture a timestamped report:

```bash
make bench-report
```

Reports are written to:
- `reports/benchmarks/`

---

## 2. Core Baselines (Enforced in Code)

The PoUW performance report evaluates benchmarks against baselines in:
- `x/pouw/keeper/performance_baselines.go`

| Benchmark | Max Avg | Max P95 | Max P99 | Min Ops/Sec | Notes |
|---|---|---|---|---|---|
| `AllInvariants` | 10ms | 25ms | 50ms | 100 | Full invariant scan |
| `ValidateParams` | 200us | 500us | 1ms | 100,000 | Param validation |
| `EndBlockConsistencyChecks` | 10ms | 25ms | 50ms | 100 | EndBlock checks |
| `PerformanceScore` | 50us | 100us | 200us | 1,000,000 | Validator scoring |

These values are intentionally conservative and must be tuned using benchmark runs on target hardware.

---

## 3. Go Benchmarks (Non-Blocking)

The following benchmark functions are available and should be monitored in CI or release gates:

- `x/pouw/keeper/e2e_test.go`
  - `BenchmarkVoteAggregation`
  - `BenchmarkSchedulerEnqueue`
- `x/pouw/keeper/devex_test.go`
  - `BenchmarkQueryServer_Job`
  - `BenchmarkQueryServer_Jobs`
  - `BenchmarkQueryServer_Params`
  - `BenchmarkMergeParams`
  - `BenchmarkDiffParams`
  - `BenchmarkRewardScaleByReputation`
- `x/pouw/keeper/observability_test.go`
  - `BenchmarkMetrics_*`
  - `BenchmarkFeeBreakdown`
  - `BenchmarkValidateParams`
- `x/verify/verify_test.go`
  - `BenchmarkTEEVerification`
  - `BenchmarkZKMLVerification`

---

## 4. Baseline Update Procedure

1. Run `make bench-report` on target hardware.
2. Save reports in `reports/benchmarks/` with build metadata.
3. Update thresholds in `x/pouw/keeper/performance_baselines.go`.
4. Document the new baselines in this file and note hardware specs.

---

## 5. Hardware and Environment Notes

Baselines must be run on representative production hardware (CPU class, memory size, disk type). Benchmark results are not comparable across different hardware or VM shapes.

---
