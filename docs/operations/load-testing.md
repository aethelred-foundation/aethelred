# Load Testing Infrastructure

## Scope

Aethelred load testing is now wired at three levels:

1. Local CLI execution using `cmd/aethelred-loadtest`.
2. CI smoke tests on pull requests.
3. Nightly baseline stress tests with artifact retention.

## Local Usage

Run a smoke profile:

```bash
go run ./cmd/aethelred-loadtest --validators 25 --jobs 200 --blocks 12 --duration 3m --block-time 2s
```

Run predefined byzantine scenario:

```bash
go run ./cmd/aethelred-loadtest --scenario byzantine
```

Run all scenarios:

```bash
go run ./cmd/aethelred-loadtest --all-scenarios
```

## CI Workflow

Workflow file: `.github/workflows/loadtest.yml`

Profiles:

- `smoke` for PRs and normal pushes.
- `baseline` for nightly schedule.
- `byzantine` and `network-stress` on manual dispatch.

Artifacts uploaded:

- `artifacts/loadtest/**`
- `loadtest-results/**`

## Release Gates

Recommended branch protection requirements:

1. `Load Test Required Gate`
2. `Audit Signoff Required Gate` (required on `main` and `release/*`)
3. `Core Required Gate`
4. `Rust Required Gate`
5. `Contracts Required Gate`
6. `Security Required Gate`

## SLO Targets

Baseline pass criteria (for release candidates):

1. Job success rate >= 99.0%.
2. Block finalization success >= 99.0%.
3. P99 consensus latency <= 2500 ms.
4. No sustained split-brain after healing in partition tests.
