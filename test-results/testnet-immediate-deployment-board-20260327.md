# Aethelred Testnet Immediate Deployment Board

Date: 2026-03-27
Status: ACTIVE -- ALL SQUADS DEPLOY NOW
Release branch: `release/testnet-v1.0`
Genesis time: 2026-04-01T14:00:00Z
Chain ID: aethelred-testnet-1

## Current State Assessment

### What Is Green (17/17 Gates Pass)

All 17 existing gates are passing from the acceptance evidence generated on 2026-03-27. The core build, test, E2E, and smoke pipelines are healthy.

### Critical Gaps Requiring Immediate Engineering

The following gaps exist between the current green gate board and a credible mainnet-parity testnet:

| Gap ID | Gap | Severity | Owner Squad | Checklist Ref |
|--------|-----|----------|-------------|---------------|
| GAP-01 | Evidence generated on feature branch, not release branch | BLOCKER | SQ01 | A.2 |
| GAP-02 | Chaos drills designed but not yet executed | BLOCKER | SQ20 | E.7 |
| GAP-03 | 24h soak test not yet run | BLOCKER | SQ07 | E.6 |
| GAP-04 | Load test not run against live testnet | HIGH | SQ07 | E.4, E.5 |
| GAP-05 | External audit signoff pending for bridge contracts | HIGH | SQ10/SQ11 | F.7 |
| GAP-06 | Kani proofs not activated in CI | HIGH | SQ18 | I.7 |
| GAP-07 | Production observability dashboards not stood up | HIGH | SQ19 | J.1-J.4 |
| GAP-08 | External validators not yet onboarded using runbook | MEDIUM | SQ15 | K.1-K.7 |
| GAP-09 | Threat model currency not verified | MEDIUM | SQ16 | I.1 |
| GAP-10 | Bug bounty scope and triage not confirmed active | MEDIUM | SQ16 | I.3 |
| GAP-11 | Status page not confirmed ready | MEDIUM | SQ19 | J.5 |
| GAP-12 | War room bridge not confirmed | MEDIUM | SQ19 | J.6 |
| GAP-13 | On-call rota not finalized with names | MEDIUM | SQ19 | J.7 |
| GAP-14 | Tokenomics parameters not confirmed frozen | MEDIUM | SQ02 | M.1 |
| GAP-15 | TGE dependencies not separated eng/non-eng | MEDIUM | SQ01 | M.6 |
| GAP-16 | Custody/signer/multisig/HSM flows not rehearsed | HIGH | SQ10 | M.3 |

## Squad-to-Checklist Mapping

### WS1: Release Control, PMO, Evidence (10 Engineers)

| Squad | Checklist Sections | Immediate Actions |
|-------|-------------------|-------------------|
| SQ01 (5 eng) | A. Release Control | 1. Merge all acceptance evidence onto `release/testnet-v1.0` 2. Re-run all gates on the release branch 3. Lock feature work off release branch 4. Create daily 18:00 pass/fail report |
| SQ02 (5 eng) | B. Chain Identity and Genesis | 1. Publish canonical `testnet-genesis.json` 2. Publish chain ID, checksum, seed peers 3. Document all mainnet parameter deviations 4. Freeze tokenomics parameters for TGE |

### WS2: Chain Core, Consensus, IBC, Verify (20 Engineers)

| Squad | Checklist Sections | Immediate Actions |
|-------|-------------------|-------------------|
| SQ03 (5 eng) | C. Runtime and Consensus | 1. Re-run go build and go test on release branch 2. Expand malformed vote / replay / divergence coverage 3. Write consensus invariant note |
| SQ04 (5 eng) | C. Runtime (IBC) | 1. Add IBC channel lifecycle tests 2. Add subscription persistence tests 3. Verify import/export safety |
| SQ05 (5 eng) | C. Runtime (Verify) | 1. Verify fail-closed production paths 2. Wire reject telemetry for verification failures 3. Verify readiness gates match launch mode |
| SQ15 (5 eng) | K. Validator Trust | 1. Rewrite runbook for April 2026 values 2. Publish image tags, chain ID, peer list 3. Write operator onboarding checklist 4. Write rollback and escalation checklists |

### WS3: E2E, Load, Exploit, Parity Testing (15 Engineers)

| Squad | Checklist Sections | Immediate Actions |
|-------|-------------------|-------------------|
| SQ06 (5 eng) | D. Testnet Rehearsal | 1. Verify local stack mirrors launch topology 2. Create `launch-candidate` E2E script 3. Standardize artifacts under `test-results/` |
| SQ07 (5 eng) | E. Performance and Resilience | 1. Run bounded testnet load scenarios 2. **RUN 24h SOAK TEST** (GAP-03) 3. Run parity profile approximating mainnet load 4. Publish baseline throughput and latency |
| (overflow from SQ20) (5 eng) | E. Performance (Chaos) | 1. **EXECUTE CHAOS DRILLS DR-01 to DR-07** (GAP-02) 2. Run validator-loss, API-loss drills 3. Record time-to-detect and time-to-recover |

### WS4: Contracts, Bridge, Governance, Vaults (15 Engineers)

| Squad | Checklist Sections | Immediate Actions |
|-------|-------------------|-------------------|
| SQ10 (5 eng) | F. Contracts, Governance | 1. Re-verify token/vesting/governance/pause controls 2. Confirm testnet deployment params match mainnet 3. **Rehearse custody/signer/multisig/HSM flows** (GAP-16) |
| SQ11 (5 eng) | F. Bridge Controls | 1. Re-run bridge replay/rate-limit tests 2. Test bridge rate limits and mint ceilings 3. Make bridge open/pause decision explicit 4. Pursue external audit signoff (GAP-05) |
| SQ14 (5 eng) | H. Developer Experience | 1. Confirm launch-scope dApps point to testnet 2. Run build/lint/test/Lighthouse checks 3. Produce launch-surface inventory |

### WS5: Rust Core, VM, Bridge, SDKs (10 Engineers)

| Squad | Checklist Sections | Immediate Actions |
|-------|-------------------|-------------------|
| SQ08 (5 eng) | G. Rust Runtime | 1. Compile workspace on release branch 2. Capture benchmark baselines 3. Decide which production stubs are testnet vs mainnet-only |
| SQ09 (5 eng) | G. Rust (VM, Bridge) | 1. Expand malformed input tests 2. Validate sandbox flows 3. Capture negative-path safety evidence |

### WS6: Verifiers, dApps, SDK Packaging, CLI (10 Engineers)

| Squad | Checklist Sections | Immediate Actions |
|-------|-------------------|-------------------|
| SQ12 (5 eng) | H. SDKs, CLI | 1. Verify 4/4 SDKs install from artifacts 2. Make CLI smoke installs deterministic 3. Publish compatibility matrix |
| SQ13 (5 eng) | H. Verifiers | 1. Validate negative paths, timeouts, retries 2. Lock API/schema compatibility 3. Rehearse testnet deployment and health checks |

### WS7: Security Verification, Fuzzing, Formal (10 Engineers)

| Squad | Checklist Sections | Immediate Actions |
|-------|-------------------|-------------------|
| SQ16 (5 eng) | I. Security Program | 1. Verify threat model is current (GAP-09) 2. Confirm bug bounty scope active (GAP-10) 3. Publish vulnerability disposition sheet |
| SQ17 (5 eng) | I. Security (Fuzzing) | 1. Expand seed corpora for consensus/bridge 2. Re-run exploit scenarios against release candidate 3. Produce local fuzz run instructions |
| SQ18 (5 eng) | I. Security (Formal) | 1. **Activate Kani proofs** (GAP-06) 2. Run Tier-1 proof targets 3. Store proof outputs with evidence |

### WS8: Observability, Ops, Upgrade, Recovery (10 Engineers)

| Squad | Checklist Sections | Immediate Actions |
|-------|-------------------|-------------------|
| SQ19 (5 eng) | J. Observability | 1. **Stand up production dashboards** (GAP-07) 2. Define SLOs 3. Validate alert paths 4. **Ready status page** (GAP-11) 5. **Set up war room bridge** (GAP-12) 6. **Finalize on-call rota** (GAP-13) |
| SQ20 (5 eng) | E. Recovery / L. Mainnet Carryover | 1. **Execute chaos drills** (GAP-02) 2. Rehearse rollback/halt/restore/upgrade 3. Produce signed dress-rehearsal report |

## Immediate Deployment Order (All Squads Start Now)

### Priority 1 -- Start Within Hours (BLOCKERS)

1. **SQ01**: Merge evidence to release branch, re-run all gates on `release/testnet-v1.0`
2. **SQ07**: Begin 24h soak test immediately
3. **SQ20**: Begin chaos drill execution DR-01 through DR-07
4. **SQ19**: Stand up production dashboards and alert routing

### Priority 2 -- Start Within 24 Hours (HIGH)

5. **SQ03**: Re-run full test suite on release branch
6. **SQ10**: Begin custody/signer/HSM rehearsal
7. **SQ11**: Pursue external audit signoff, re-run bridge tests
8. **SQ18**: Activate Kani proofs for Tier-1 targets

### Priority 3 -- Start Within 48 Hours (MEDIUM + Parallel)

9. **SQ02**: Publish canonical genesis, freeze tokenomics
10. **SQ04**: IBC lifecycle tests expansion
11. **SQ05**: Verify fail-closed paths
12. **SQ06**: Create launch-candidate E2E script
13. **SQ08**: Rust benchmark baselines
14. **SQ09**: Malformed input test expansion
15. **SQ12**: SDK artifact install verification
16. **SQ13**: Verifier negative path validation
17. **SQ14**: dApp testnet endpoint verification
18. **SQ15**: Runbook rewrite for April 2026
19. **SQ16**: Threat model review, bug bounty confirmation
20. **SQ17**: Fuzz seed corpus expansion

## Acceptance Commands (Run on release/testnet-v1.0)

```bash
# -- SQ01 must run these on the release branch and archive outputs --

# Core build and test
go build ./cmd/aethelredd
go test ./...

# Rust workspace
cargo test --manifest-path crates/Cargo.toml --workspace --no-run

# Local testnet lifecycle
./scripts/devtools-local-testnet.sh up
./scripts/devtools-local-testnet.sh doctor
./scripts/devtools-cli-smoke.sh
go test -run TestEndToEnd ./x/pouw/keeper/...
go run ./run_exploit_simulations.go
go run ./cmd/aethelred-loadtest --all-scenarios --validators 25 --blocks 50 --duration 2m
./scripts/devtools-local-testnet.sh down -v

# Fuzz check
make fuzz-check

# Contracts
cd contracts && forge test && cd ..

# SDK version check
make sdk-version-check
```

## Daily 18:00 Reporting Format

Each squad lead reports:

```
Squad: SQ##
Status: GREEN / AMBER / RED
Gates owned: [list]
Today: [what was completed]
Blockers: [any blockers]
Evidence: [artifact paths]
Tomorrow: [next actions]
```

## Minimum Bar Before Testnet Launch

From the checklist, these must ALL be true:

1. Chain starts cleanly and finalizes reliably
2. External validators can join from docs alone
3. Public RPC, explorer, faucet, and verifiers are stable
4. Performance and exploit gates are trustworthy
5. Rollback and recovery have been rehearsed
6. Every lesson from testnet is converted into a mainnet/TGE work item

## Commander Assignments (Replace With Real Names)

| Role | Placeholder | Responsibility |
|------|-------------|----------------|
| Release Commander | E001 | Gate board truth, release branch integrity |
| Security Commander | E076 | Vulnerability disposition, audit signoff |
| SRE Commander | E091 | Observability, on-call, incident readiness |
| Program Commander | E001 (dual) | Daily reporting, cross-squad coordination |
