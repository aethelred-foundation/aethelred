# Aethelred Unified Launch Deployment -- All Three Source Documents

Date: 2026-03-27
Mode: IMMEDIATE DEPLOYMENT -- ALL DATES COLLAPSED TO NOW
Genesis Target: 2026-04-01T14:00:00Z
Chain ID: aethelred-testnet-1

## Source Documents

1. `testnet-to-mainnet-and-tge-checklist-20260327.md` -- 13 sections (A-M), ~80 gates
2. `testnet-mainnet-parity-engineering-board-20260327.md` -- 20 squads, 100 engineers
3. `aethelred_launch_program_updated_20260327.xlsx` -- 76 unique tasks (312 daily entries), 27 launch checklist items, 100 engineer roster, resource stack

## Status Override

The spreadsheet shows **311 of 312 task entries as "Not Started"** and all **27 launch checklist items as "Not Started"**. Per directive, ALL tasks deploy NOW regardless of their original Feb 15 - Jul 1 schedule.

## Engineer Roster -- Roles Per Squad

Each squad has 5 engineers with dedicated roles:

| Role | Responsibility |
|------|---------------|
| **Lead** | Owns the squad signoff. Accountable for all gates. |
| **Build/Impl** | Writes code, fixes pipelines, produces builds. |
| **Test/Validation** | Writes and runs tests, validates edge cases. |
| **Docs/Evidence** | Collects artifacts, writes documentation, records evidence. |
| **Ops/Release** | Runs rehearsals, packages for release, operates tooling. |

## Squad Deployment With Integrated Tasks

### SQ01: Release Freeze and Candidate Control (E001-E005)

**Track**: Program Control
**Mainnet Value**: Release like mainnet, not like a beta

Launch Checklist Item: `Frozen release branch exists and feature work is blocked` (Hard Gate, Pre-Testnet)

Spreadsheet Tasks (12 unique, deploy ALL now):
- [ ] Define Testnet v1 scope and parameter sheet (P0 Critical, GATE)
- [ ] Key management and multisig policy draft (P0 Critical, GATE)
- [ ] Testnet RC1 build pipeline with signed artifacts (P0 Critical, GATE)
- [ ] MAINNET CODE FREEZE + RC1 tag (GATE)
- [ ] Mainnet RC tag + code freeze enforcement (GATE)
- [ ] Multi-party hash verification + attestation collection (GATE)
- [ ] Security: finalize reproducible build verification checklist (GATE)
- [ ] Adversarial drill: spam + mempool flooding (GATE)
- [ ] Developer portal IA + docs skeleton published
- [ ] Legal: publish testnet disclaimer + risk notices
- [ ] ADGM DLT Foundation: charter + governance mapping
- [ ] Patch release process (fixes + changelog)

Engineer Actions:
- E001 (Lead): Own freeze branch, merge evidence to `release/testnet-v1.0`
- E002 (Build/Impl): Build machine-readable gate board, RC pipeline
- E003 (Test/Validation): Lock branch rules, validate exception path
- E004 (Docs/Evidence): Standardize evidence retention and naming
- E005 (Ops/Release): Run daily 18:00 pass/fail reporting

---

### SQ02: Genesis, Parameters, and Chain Identity (E006-E010)

**Track**: Chain Identity
**Mainnet Value**: Operators boot the same artifact that launch signs off

Launch Checklist Item: `Canonical testnet genesis, chain ID, checksum, and peer list are published` (Hard Gate, Pre-Testnet)

Spreadsheet Tasks (8 unique, deploy ALL now):
- [ ] Genesis schema and chain-id strategy finalized (P0 Critical, GATE)
- [ ] Finalize Testnet genesis params + freeze (GATE)
- [ ] Protocol: freeze emissions/fees/slashing params in genesis spec (GATE)
- [ ] Genesis participant list locked + comms sent (GATE)
- [ ] Key submission window opens / secure intake (GATE)
- [ ] Genesis.json generated + internal hash published (GATE)
- [ ] Publish genesis.json hash publicly + verification guide (GATE)
- [ ] Public genesis hash publication + verification guide

Engineer Actions:
- E006 (Lead): Own genesis bundle
- E007 (Build/Impl): Finalize chain ID and params
- E008 (Test/Validation): Publish peer list and allocations
- E009 (Docs/Evidence): Generate checksum and operator verification guide
- E010 (Ops/Release): Prepare genesis publication package

---

### SQ03: Validator Build and Consensus Correctness (E011-E015)

**Track**: Consensus Correctness
**Mainnet Value**: Consensus behavior under testnet mirrors intended mainnet behavior

Launch Checklist Item: `Validator binary builds and full Go test suite passes on candidate` (Hard Gate, Pre-Testnet)

Spreadsheet Tasks (4 unique, deploy ALL now):
- [ ] Determinism and replay test suite baseline (P0 Critical, GATE)
- [ ] Close P0 bugs for Testnet launch candidate (GATE)
- [ ] Protocol: apply audit fixes and run full regression suite (GATE)
- [ ] Legal/Protocol: tokenomics and governance decision log update

Engineer Actions:
- E011 (Lead): Own validator build and consensus signoff
- E012 (Build/Impl): Keep validator binary green
- E013 (Test/Validation): Expand malformed/replay/divergent vote tests
- E014 (Docs/Evidence): Write consensus invariant note
- E015 (Ops/Release): Prepare multi-validator rehearsal evidence

---

### SQ04: IBC and State-Machine Reliability (E016-E020)

**Track**: IBC and State
**Mainnet Value**: State-machine correctness before scale

Launch Checklist Item: `Channel lifecycle, replay, and malformed-state regressions are green` (Hard Gate, Pre-Testnet)

Primary paths: `x/ibc/keeper/`, `x/ibc/types/`

Engineer Actions:
- E016 (Lead): Own IBC reliability signoff
- E017 (Build/Impl): Fix or confirm storage semantics
- E018 (Test/Validation): Add lifecycle and corruption tests
- E019 (Docs/Evidence): Document import/export safety evidence
- E020 (Ops/Release): Run IBC regression pack

---

### SQ05: Verification Pipeline and Seal Fail-Closed Paths (E021-E025)

**Track**: Verify and Seal
**Mainnet Value**: Same safety posture, with testnet-only allowances documented

Launch Checklist Item: `Production fail-closed paths and testnet exceptions are explicitly tested` (Hard Gate, Pre-Testnet)

Primary paths: `app/readiness.go`, `x/verify/`, `x/seal/`

Engineer Actions:
- E021 (Lead): Own fail-closed verification posture
- E022 (Build/Impl): Expand negative-path verify tests
- E023 (Test/Validation): Validate network-mode readiness behavior
- E024 (Docs/Evidence): Collect reject telemetry evidence
- E025 (Ops/Release): Prepare testnet/prod mode documentation

---

### SQ06: E2E Truthfulness and Local Testnet Parity (E026-E030)

**Track**: E2E Parity
**Mainnet Value**: Dress rehearsal should feel like launch day

Launch Checklist Item: `Local mainnet-parity stack boots, doctors cleanly, and CLI smoke passes` (Hard Gate, Pre-Testnet)

Engineer Actions:
- E026 (Lead): Own E2E truthfulness
- E027 (Build/Impl): Repair stale paths and flags
- E028 (Test/Validation): Separate real-node vs simulated artifacts
- E029 (Docs/Evidence): Document launch-candidate E2E path
- E030 (Ops/Release): Run repeatable local stack rehearsal

---

### SQ07: Load, Exploit, and Scenario Harness (E031-E035)

**Track**: Load and Exploit
**Mainnet Value**: Performance and resilience are release signals, not demos

Launch Checklist Item: `Bounded parity profile passes with objective thresholds` (Hard Gate, Pre-Testnet)

**BLOCKER**: 24h soak test must start immediately.

Engineer Actions:
- E031 (Lead): Own load/exploit release signal -- **START SOAK TEST NOW**
- E032 (Build/Impl): Fix --all-scenarios behavior
- E033 (Test/Validation): Define pass/fail thresholds
- E034 (Docs/Evidence): Publish seeded/unseeded evidence bundle
- E035 (Ops/Release): Run parity-profile rehearsal

---

### SQ08: Rust Core and Consensus Readiness (E036-E040)

**Track**: Rust Core
**Mainnet Value**: No false promise on Rust readiness

Launch Checklist Item: `Rust workspace compiles cleanly and testnet gating is truthful` (Hard Gate, Pre-Testnet)

Engineer Actions:
- E036 (Lead): Own Rust core readiness note
- E037 (Build/Impl): Keep workspace compile green
- E038 (Test/Validation): Separate hygiene from production-stub blockers
- E039 (Docs/Evidence): Document feature-gap truthfully
- E040 (Ops/Release): Capture benchmark baselines

---

### SQ09: Rust VM, Bridge, and Sandbox Safety (E041-E045)

**Track**: Rust VM and Bridge
**Mainnet Value**: Runtime edge cases found before public traffic

Engineer Actions:
- E041 (Lead): Own Rust VM/bridge safety signoff
- E042 (Build/Impl): Add malformed input checks
- E043 (Test/Validation): Expand state-machine regressions
- E044 (Docs/Evidence): Collect sandbox/vault evidence
- E045 (Ops/Release): Prepare reproducible run commands

---

### SQ10: Contracts Token, Governance, and Timelock (E046-E050)

**Track**: Contracts Controls
**Mainnet Value**: Governance behaves like mainnet from day one

Launch Checklist Item: `Governance, token, vesting, bridge, and vault controls are reviewed and tested` (Hard Gate, Pre-Testnet)

Spreadsheet Tasks (integrated from SQ18 tokenomics track):
- [ ] Finalize tokenomics parameters / freeze milestone prep (GATE)
- [ ] TOKENOMICS AND GOVERNANCE FREEZE v1 (GATE)

Engineer Actions:
- E046 (Lead): Own governance and token control matrix
- E047 (Build/Impl): Refresh token and vesting invariants
- E048 (Test/Validation): Refresh pause and delay controls
- E049 (Docs/Evidence): Document deployment parameters
- E050 (Ops/Release): Package contract control evidence, **rehearse custody/HSM flows**

---

### SQ11: Contracts Bridge, Vault, and Reserve Automation (E051-E055)

**Track**: Bridge and Vaults
**Mainnet Value**: High-risk value paths are controlled before exposure

Engineer Actions:
- E051 (Lead): Own bridge/vault hardening signoff, **pursue audit signoff**
- E052 (Build/Impl): Expand replay and accounting tests
- E053 (Test/Validation): Expand vault solvency tests
- E054 (Docs/Evidence): Document bridge open/pause criteria
- E055 (Ops/Release): Map controls to monitoring/runbooks

---

### SQ12: SDK Packaging and CLI Release Path (E056-E060)

**Track**: SDKs and CLI
**Mainnet Value**: Integrators experience mainnet-grade packaging quality

Launch Checklist Item: `SDKs and CLI install from artifacts on clean environments` (Hard Gate, Pre-Testnet)

Engineer Actions:
- E056 (Lead): Own SDK/CLI release path
- E057 (Build/Impl): Fix artifact-first packaging
- E058 (Test/Validation): Validate clean install/build paths
- E059 (Docs/Evidence): Publish compatibility matrix
- E060 (Ops/Release): Collect operator smoke evidence

---

### SQ13: Verifier Services and Integrations (E061-E065)

**Track**: Verifier and Services
**Mainnet Value**: Public verification path must fail safely

Launch Checklist Item: `FastAPI and Next.js verifiers pass health and negative-path checks` (Hard Gate, Pre-Testnet)

Spreadsheet Tasks (4 unique, deploy ALL now):
- [ ] Explorer decision + deployment plan
- [ ] Faucet spec + staging deployment
- [ ] Deploy explorer + indexer production (GATE)
- [ ] Deploy public RPC + seed nodes multi-region (GATE)

Engineer Actions:
- E061 (Lead): Own verifier services signoff
- E062 (Build/Impl): Deploy explorer and RPC nodes
- E063 (Test/Validation): Validate negative paths, timeouts, retries
- E064 (Docs/Evidence): Lock API/schema compatibility
- E065 (Ops/Release): Rehearse testnet deployment and health checks

---

### SQ14: dApps Testnet Surface and UX Hardening (E066-E070)

**Track**: dApps Surface
**Mainnet Value**: Public testnet experience is deliberate, not accidental

Engineer Actions:
- E066 (Lead): Own launch-scope dApp decision
- E067 (Build/Impl): Fix endpoints to point to testnet
- E068 (Test/Validation): Run build/lint/test/Lighthouse
- E069 (Docs/Evidence): Produce public surface inventory
- E070 (Ops/Release): Prepare launch-scope deployment

---

### SQ15: Validator Ops, Runbooks, and Launch Docs (E071-E075)

**Track**: Validator Ops
**Mainnet Value**: Operator experience mirrors mainnet onboarding

Launch Checklist Items:
- `Validator runbook, operator onboarding, rollback, and incident docs are current` (Hard Gate, Pre-Testnet)
- `Minimum 7 validators across 3 regions and 2 providers` (Hard Gate, Active Testnet)

Spreadsheet Tasks (11 unique, deploy ALL now):
- [ ] Validator hardware profile published (min/recommended)
- [ ] Validator onboarding runbook v1
- [ ] Validator onboarding sessions + support office hours
- [ ] PUBLIC TESTNET LAUNCH: dev quickstart + faucet live (GATE)
- [ ] DevRel: publish dApp quickstart + sample app
- [ ] Ops: validator uptime scoring + remediation outreach
- [ ] DevRel: publish tokenomics/governance docs for validators
- [ ] Finalize mainnet docs portal (validators + devs)
- [ ] Legal: execute validator agreements + SLA countersigns
- [ ] Ops: confirm validator endpoints + launch-day connectivity (GATE)
- [ ] Legal: confirm all validator agreements/SLA executed

Engineer Actions:
- E071 (Lead): Own runbook and operator signoff
- E072 (Build/Impl): Rewrite runbook for April 2026 values
- E073 (Test/Validation): **Test: have external validator join from docs only**
- E074 (Docs/Evidence): Publish image tags, chain ID, peer list, faucet, explorer
- E075 (Ops/Release): Write rollback and escalation checklists

---

### SQ16: Security Scans and Dependency Hygiene (E076-E080)

**Track**: Dependency Hygiene
**Mainnet Value**: Security posture is visible and defendable

Launch Checklist Item (shared): `Threat model, bug bounty, disclosure policy, and scan triage are active` (Hard Gate, Active Testnet)

Spreadsheet Tasks (2 unique):
- [ ] Reproducible builds + signed release artifacts / supply chain (GATE)
- [ ] Protocol/Security: final RC hash + binary verification sign-off (GATE)

Engineer Actions:
- E076 (Lead): Own vulnerability disposition signoff
- E077 (Build/Impl): Continue moderate backlog reduction
- E078 (Test/Validation): Reconcile scan outputs across Go, Rust, JS, contracts
- E079 (Docs/Evidence): Publish release-candidate vulnerability disposition sheet
- E080 (Ops/Release): Separate real findings from dev-only/accepted-risk items

---

### SQ17: Fuzzing and Adversarial Test Depth (E081-E085)

**Track**: Security Verification
**Mainnet Value**: Auditor-grade abuse coverage

Spreadsheet Tasks (10 unique, deploy ALL now):
- [ ] Threat model workshop: consensus + P2P (P0 Critical, GATE)
- [ ] Fuzzing harness enabled for tx/mempool parsers
- [ ] Audit #1 kickoff: architecture + consensus (P0 Critical, GATE)
- [ ] Audit #1 interim findings triage + patch plan (GATE)
- [ ] Bug bounty program prep (scope, rules, payouts)
- [ ] Bug bounty launch + triage ops
- [ ] Audit #2 kickoff: mainnet readiness (GATE)
- [ ] BUG BOUNTY GO-LIVE + triage rota (GATE)
- [ ] Publish security disclosure policy + responsible disclosure page
- [ ] Audit #2 final report review + remediation closure (GATE)

Engineer Actions:
- E081 (Lead): Own fuzz and adversarial signoff
- E082 (Build/Impl): Expand seed corpora for consensus/bridge/verifier
- E083 (Test/Validation): Re-run exploit scenarios against launch candidate
- E084 (Docs/Evidence): Produce local fuzz run instructions
- E085 (Ops/Release): Capture crash triage ownership and SLA

---

### SQ18: Formal Verification and Spec Discipline (E086-E090)

**Track**: Formal and Specs
**Mainnet Value**: Proof claims stay credible under audit

Launch Checklist Item: `Tier 1 proof targets have real outputs attached to candidate` (Hard Gate, Mainnet Freeze)

Spreadsheet Tasks (4 unique):
- [ ] Finalize tokenomics parameters / freeze milestone prep (GATE)
- [ ] TOKENOMICS AND GOVERNANCE FREEZE v1 (GATE)
- [ ] Legal: finalize tokenomics paper + disclosures (GATE)
- [ ] Legal: finalize disclosure pack for mainnet launch

Engineer Actions:
- E086 (Lead): Own formal verification signoff, **activate Kani proofs**
- E087 (Build/Impl): Run Tier-1 proof commands locally
- E088 (Test/Validation): Distinguish scaffolding from live proof jobs
- E089 (Docs/Evidence): Publish proof backlog with status per target
- E090 (Ops/Release): Store proof outputs with candidate evidence

---

### SQ19: Observability, SLOs, and On-Call Readiness (E091-E095)

**Track**: Observability
**Mainnet Value**: Mainnet-style operating picture before public traffic

Launch Checklist Items:
- `Prometheus/Grafana/Loki/Alertmanager dashboards and paging are active` (Hard Gate, Pre-Testnet)
- `Public RPC, explorer, faucet, verifiers, and dashboard stay green under load` (Hard Gate, Active Testnet)

Spreadsheet Tasks (9 unique, deploy ALL now):
- [ ] Monitoring architecture selected (P0 Critical, GATE)
- [ ] Launch comms + status page + incident channels
- [ ] PUBLIC TESTNET LAUNCH: monitoring/explorer/RPC green (GATE)
- [ ] Weekly network health report and KPI dashboard update
- [ ] Ops: WAF/rate limiting tuned for RPC endpoints
- [ ] Ops: mainnet infra cutover plan + failover drill scheduled
- [ ] Mainnet infra deploy: RPC, seed nodes, monitoring (GATE)
- [ ] MAINNET LAUNCH: security monitoring + incident readiness (GATE)
- [ ] MAINNET LAUNCH: explorer/RPC/status page stability (GATE)

Engineer Actions:
- E091 (Lead): Own observability signoff, **stand up dashboards NOW**
- E092 (Build/Impl): Deploy Prometheus/Grafana/Loki stack
- E093 (Test/Validation): Validate alert paths using known-failure drills
- E094 (Docs/Evidence): Define SLOs, document alert routing
- E095 (Ops/Release): **Finalize on-call rota, set up war room bridge, ready status page**

---

### SQ20: Upgrade, Recovery, and Chaos Rehearsal (E096-E100)

**Track**: Upgrade and Recovery
**Mainnet Value**: Mainnet launch muscles are built on testnet

Launch Checklist Items:
- `Rollback, halt, restore, and upgrade drills are rehearsed` (Hard Gate, Pre-Testnet)
- `On-call schedule, war room, status page, and paging are final` (Hard Gate, Mainnet Freeze)

Spreadsheet Tasks (from incident response track):
- [ ] Incident response playbook v1 (P0 Critical, GATE)

Engineer Actions:
- E096 (Lead): Own recovery signoff, **START CHAOS DRILLS NOW**
- E097 (Build/Impl): Script drills DR-01 through DR-07
- E098 (Test/Validation): Record time-to-detect and time-to-recover
- E099 (Docs/Evidence): Produce operator action timelines and playbooks
- E100 (Ops/Release): Produce signed testnet dress-rehearsal report

## Consolidated Launch Checklist (27 Items From Spreadsheet)

### Pre-Testnet (14 Hard Gates) -- ALL START NOW

| # | Item | Owner | Status |
|---|------|-------|--------|
| 1 | Frozen release branch exists | SQ01 | Not Started |
| 2 | Canonical testnet genesis published | SQ02 | Not Started |
| 3 | Validator binary builds + test suite passes | SQ03 | Not Started |
| 4 | IBC lifecycle regressions green | SQ04 | Not Started |
| 5 | Fail-closed paths and testnet exceptions tested | SQ05 | Not Started |
| 6 | Local stack boots + doctor + CLI smoke passes | SQ06 | Not Started |
| 7 | Bounded parity profile passes | SQ07 | Not Started |
| 8 | Rust workspace compiles + gating truthful | SQ08 | Not Started |
| 9 | Contract controls reviewed and tested | SQ10/SQ11 | Not Started |
| 10 | SDKs + CLI install from artifacts | SQ12 | Not Started |
| 11 | Verifiers pass health + negative-path checks | SQ13 | Not Started |
| 12 | Validator runbook + docs current | SQ15 | Not Started |
| 13 | Observability dashboards + paging active | SQ19 | Not Started |
| 14 | Recovery drills rehearsed | SQ20 | Not Started |

### Active Testnet (4 Gates) -- Prepare NOW

| # | Item | Owner | Status |
|---|------|-------|--------|
| 15 | Min 7 validators, 3 regions, 2 providers | SQ15/SQ19 | Not Started |
| 16 | Public infra stays green under load | SQ13/SQ19 | Not Started |
| 17 | Security program active | SQ16/SQ17/SQ18 | Not Started |
| 18 | Weekly review published | SQ01/SQ19 | Not Started |

### Post-Testnet Hardening (2 Gates)

| # | Item | Owner | Status |
|---|------|-------|--------|
| 19 | Testnet findings -> backlog with owners | SQ01 | Not Started |
| 20 | Soak/chaos benchmarks trended | SQ07/SQ19/SQ20 | Not Started |

### Mainnet Freeze (3 Gates)

| # | Item | Owner | Status |
|---|------|-------|--------|
| 21 | Mainnet RC reproducible + signed | SQ01/SQ16 | Not Started |
| 22 | Tier 1 proof targets have outputs | SQ18 | Not Started |
| 23 | On-call + war room + status page final | SQ19/SQ20 | Not Started |

### Mainnet Launch (1 Gate)

| # | Item | Owner | Status |
|---|------|-------|--------|
| 24 | Launch: chain starts, finality, public infra | SQ20 | Not Started |

### TGE Readiness (3 Gates)

| # | Item | Owner | Status |
|---|------|-------|--------|
| 25 | Tokenomics/vesting/governance frozen + signed | SQ10/SQ18 | Not Started |
| 26 | Custody/multisig/HSM/exchange packs rehearsed | SQ15/SQ20 | Not Started |
| 27 | Public disclosures finalized | SQ01 | Not Started |

## Resource Stack (From Spreadsheet)

| Domain | Primary Owner | Key Tools |
|--------|--------------|-----------|
| Release control | SQ01/SQ16 | Git, GitHub, gh CLI, signed checksums, SBOMs |
| Genesis and network | SQ02/SQ15 | Genesis generator, Docker testnet, secure validator intake |
| Go runtime | SQ03/SQ04/SQ05 | Go 1.24+, Makefile, unit/integration tests |
| Rust runtime | SQ08/SQ09 | Cargo, clippy, benchmarks, feature gating |
| Contracts | SQ10/SQ11/SQ17/SQ18 | Hardhat, Foundry, Slither, Echidna |
| Load and exploit | SQ07/SQ17 | Custom loadtest, exploit simulations, seeded scenarios |
| Verifiers and services | SQ13 | FastAPI, Next.js, health probes, schema checks |
| SDK and CLI | SQ12 | npm, pip, cargo, Go modules, clean-room installers |
| Observability | SQ19 | Prometheus, Grafana, Loki, Alertmanager, OpenTelemetry |
| Infrastructure | SQ15/SQ19/SQ20 | Docker, cloud instances, sentry nodes, RPC fleet |
| Security program | SQ16/SQ17/SQ18 | Threat register, bug bounty, Trivy, gosec, cargo audit |
| Recovery and launch ops | SQ20 | War room, rollback playbooks, restore scripts |
| TGE readiness | SQ10/SQ15/SQ18/SQ20 | Tokenomics, vesting, multisig/HSM, exchange packs |

## Related Artifacts

- `test-results/testnet-immediate-deployment-board-20260327.md` -- Gap analysis and priority ordering
- `test-results/testnet-launch-gate-board-v3.json` -- 33-gate machine-readable board
- `test-results/commander-immediate-actions-20260327.md` -- Blocker resolution commands
- `docs/operations/daily-squad-report-template.md` -- Daily 18:00 reporting format
- `test-results/acceptance-evidence-20260327.md` -- Previous 17/17 gate evidence
