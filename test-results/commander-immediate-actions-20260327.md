# Commander Immediate Actions -- Testnet Launch

Date: 2026-03-27
Board: testnet-immediate-deployment-board-20260327.md
Gate Board: testnet-launch-gate-board-v3.json (v3.0.0)

## Status: 17/33 Gates Pass -- 3 BLOCKERS -- 16 Pending

## BLOCKER Resolution (Must Start Within Hours)

### BLOCKER-1: Release Branch Evidence (SQ01)

The acceptance evidence was generated on `feat/dapps-protocol-updates-2026-03-16`, not on `release/testnet-v1.0`. The checklist requires all signoff to be performed on the frozen branch.

**Action**:
```bash
# SQ01 Lead executes:
git checkout release/testnet-v1.0
git merge feat/dapps-protocol-updates-2026-03-16  # or cherry-pick relevant commits

# Then re-run all acceptance commands on release branch:
go build ./cmd/aethelredd
go test ./...
cargo test --manifest-path crates/Cargo.toml --workspace --no-run
./scripts/devtools-local-testnet.sh up
./scripts/devtools-local-testnet.sh doctor
./scripts/devtools-cli-smoke.sh
go test -run TestEndToEnd ./x/pouw/keeper/...
go run ./run_exploit_simulations.go
go run ./cmd/aethelred-loadtest --all-scenarios --validators 25 --blocks 50 --duration 2m
./scripts/devtools-local-testnet.sh down -v

# Archive outputs with release-branch prefix
```

**Gate ID**: `release_branch_signoff`
**Owner**: SQ01 Lead (E001)

### BLOCKER-2: 24-Hour Soak Test (SQ07)

No soak test has been run. This is a hard requirement from the checklist (Section E.6).

**Action**:
```bash
# SQ07 Lead starts the soak test immediately:
# 1. Boot local testnet or staging testnet
./scripts/devtools-local-testnet.sh up

# 2. Run extended load test (24h minimum)
go run ./cmd/aethelred-loadtest \
  --validators 7 \
  --blocks 0 \
  --duration 24h \
  --scenario parity-mainnet \
  2>&1 | tee test-results/soak-test-24h-$(date +%Y%m%d-%H%M%S).log

# 3. During soak, monitor:
#    - finalized blocks (must be continuous)
#    - completed jobs
#    - verifier errors (must be zero or documented)
#    - split-brain events (must be zero)
#    - memory/CPU trends
```

**Gate ID**: `soak_test_24h`
**Owner**: SQ07 Lead (E031)

### BLOCKER-3: Chaos Drill Execution (SQ20)

7 drills (DR-01 to DR-07) are designed but not executed. The testnet cannot be called mainnet-parity without rehearsed recovery.

**Action**:
```bash
# SQ20 Lead begins drill execution:
# DR-01: Single validator loss
# DR-02: Minority validator loss (< 1/3)
# DR-03: API endpoint loss
# DR-04: Verifier degradation
# DR-05: Bridge pause/resume
# DR-06: Chain halt and restart
# DR-07: Full rollback to previous state

# Each drill must record:
# - time-to-detect
# - time-to-recover
# - operator actions taken
# - lessons learned

# Output: test-results/chaos-drill-execution-$(date +%Y%m%d).md
```

**Gate ID**: `chaos_drill_execution`
**Owner**: SQ20 Lead (E096)

## HIGH Priority Actions (Start Within 24 Hours)

| Gate ID | Action | Owner | Command/Evidence |
|---------|--------|-------|-----------------|
| `live_testnet_loadtest` | Run load test against staging/live topology | SQ07 | `go run ./cmd/aethelred-loadtest --all-scenarios` |
| `bridge_audit_signoff` | Pursue external audit contact, run Slither/Echidna | SQ11 | `cd contracts && slither . && echidna .` |
| `kani_proofs_active` | Run Tier-1 Kani proofs locally | SQ18 | `cargo kani --harness <target>` per proof backlog |
| `prod_dashboards` | Deploy Grafana/Prometheus stack to staging | SQ19 | Infrastructure Helm charts in `infrastructure/kubernetes/` |
| `custody_hsm_rehearsal` | Rehearse multisig/HSM signing flows | SQ10 | Manual ceremony with documented steps |

## MEDIUM Priority Actions (Start Within 48 Hours)

| Gate ID | Action | Owner |
|---------|--------|-------|
| `external_validator_onboard` | Have one external person join testnet using only docs | SQ15 |
| `threat_model_current` | Review and update threat register for 2026 | SQ16 |
| `bug_bounty_active` | Confirm bounty program scope and triage on platform | SQ16 |
| `status_page_ready` | Deploy status page (Statuspage.io or equivalent) | SQ19 |
| `war_room_bridge` | Set up Slack/Discord bridge for launch week | SQ19 |
| `oncall_rota_final` | Assign real names to on-call roster template | SQ19 |
| `tokenomics_frozen` | Get written approval on tokenomics parameters | SQ02 |
| `tge_dependency_separation` | Produce eng vs non-eng TGE task matrix | SQ01 |

## Cross-Squad Dependencies

```
SQ01 (release branch) ----> ALL SQUADS (re-run gates on release branch)
SQ07 (soak test) ----> SQ06 (testnet must be running)
SQ20 (chaos drills) ----> SQ06 (testnet must be running)
                     ----> SQ19 (dashboards must be up to observe drills)
SQ18 (Kani proofs) ----> SQ08 (Rust workspace must compile)
SQ11 (bridge audit) ----> SQ10 (contracts controls must be current)
SQ15 (validator onboard) ----> SQ02 (genesis and peer list must be published)
```

## Critical Path to Launch (April 1)

```
Day 0 (Mar 27): Deploy all 20 squads. Start soak test. Start chaos drills.
Day 1 (Mar 28): Merge to release branch. Re-run all gates. Stand up dashboards.
Day 2 (Mar 29): Continue soak test. Execute remaining drills. Run Kani proofs.
Day 3 (Mar 30): Complete soak test. Finalize on-call. External validator test.
Day 4 (Mar 31): Full dress rehearsal on frozen candidate. Commander sign-off.
Day 5 (Apr 01): Genesis at 14:00 UTC. Launch.
```

## Evidence Produced Today

- `test-results/testnet-immediate-deployment-board-20260327.md` (this deployment board)
- `test-results/testnet-launch-gate-board-v3.json` (expanded gate board with 33 gates)
- `docs/operations/daily-squad-report-template.md` (daily reporting template)
- `test-results/commander-immediate-actions-20260327.md` (this document)
- Go build verified PASS on current branch (2026-03-27)
- Go test suite running (background)
- Rust workspace compile running (background)
