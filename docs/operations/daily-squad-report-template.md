# Daily Squad Report Template

Date: YYYY-MM-DD
Report time: 18:00 UTC
Release branch: `release/testnet-v1.0`

## Instructions

Each squad lead submits this report by 18:00 daily. Only artifact-backed claims count.

## Squad Report

### Squad: SQ##
**Lead**: [Name]
**Status**: GREEN / AMBER / RED

**Gates Owned**:
- [ ] Gate 1 (ID: `gate_id`) -- STATUS
- [ ] Gate 2 (ID: `gate_id`) -- STATUS

**Today**:
1. [Completed task with artifact path]
2. [Completed task with artifact path]

**Blockers**:
- [Blocker description and required resolution]

**Evidence Produced**:
- `test-results/[artifact-name].txt`
- `test-results/[artifact-name].json`

**Tomorrow**:
1. [Next action]
2. [Next action]

---

## Aggregate Summary (Filled by Program Commander)

| Workstream | Squads | Status | Gates Pass | Gates Pending | Blockers |
|------------|--------|--------|------------|---------------|----------|
| WS1 Release/PMO | SQ01, SQ02 | | /5 | | |
| WS2 Chain Core | SQ03, SQ04, SQ05, SQ15 | | /8 | | |
| WS3 E2E/Load | SQ06, SQ07, SQ20 | | /6 | | |
| WS4 Contracts | SQ10, SQ11, SQ14 | | /5 | | |
| WS5 Rust | SQ08, SQ09 | | /2 | | |
| WS6 SDKs/Verifiers | SQ12, SQ13 | | /3 | | |
| WS7 Security | SQ16, SQ17, SQ18 | | /5 | | |
| WS8 Observability | SQ19, SQ20 | | /6 | | |

**Overall**: ##/33 gates pass | ## pending | ## blockers

## Go/No-Go Signal

- [ ] All BLOCKER gates are PASS
- [ ] All HIGH gates are PASS or have documented exceptions
- [ ] Acceptance commands run on `release/testnet-v1.0` and archived
- [ ] Commander sign-off: Release / Security / SRE / Program
