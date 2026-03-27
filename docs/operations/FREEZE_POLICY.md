# Release Freeze Policy

Effective: 2026-03-25
Owner: Release Engineering / RC-01 Committee
Applies to: All branches targeting testnet or mainnet releases

---

## 1. Freeze Windows

### Testnet Freeze (Incentivized Testnet Launch: April 1, 2026)

| Phase | Window | Dates | Allowed Changes |
|-------|--------|-------|-----------------|
| Soft freeze | T-7 days | March 25 - March 29, 2026 | Bug fixes, documentation, test improvements only. No new features. |
| Hard freeze | T-72 hours | March 29, 2026 00:00 UTC - April 1, 2026 | Security fixes only (requires RC-01 approval). |
| Release cut | T-0 | April 1, 2026 | Tag cut from frozen branch. No merges. |

### Mainnet Freeze (Mainnet Launch: December 10, 2026)

| Phase | Window | Dates | Allowed Changes |
|-------|--------|-------|-----------------|
| Feature freeze | T-8 weeks | October 15, 2026 | No new features merged to release branch. Bug fixes, performance, docs only. |
| Soft freeze | T-2 weeks | November 26, 2026 | Bug fixes and documentation only. No refactors. |
| Hard freeze | T-72 hours | December 7, 2026 00:00 UTC - December 10, 2026 | Security fixes only (requires RC-01 approval). |
| Release cut | T-0 | December 10, 2026 | Tag cut from frozen branch. No merges. |

---

## 2. Allowed Changes During Freeze

### Soft Freeze

- Bug fixes with regression tests
- Documentation corrections
- Test coverage improvements
- CI/CD configuration fixes (non-functional)
- Dependency security patches (via `cargo audit` / `govulncheck` / `npm audit`)

### Hard Freeze

- **Security fixes only**, subject to the exception process below
- No dependency updates unless required by a security fix
- No documentation changes (docs are frozen with the release)
- No CI configuration changes

---

## 3. Exception Process

During a hard freeze, any merge requires explicit RC-01 Committee approval.

### RC-01 Committee

| Role | Responsibility |
|------|---------------|
| Release Manager | Chairs the committee, makes final merge decision |
| Security Lead | Assesses severity and validates the fix |
| Protocol Lead | Confirms consensus/protocol safety |
| QA Lead | Validates test coverage and regression risk |

Quorum: At least 3 of 4 members must approve.

### Exception Request Requirements

To request a freeze exception, open a GitHub Issue using the `freeze-exception` label with:

1. **Severity justification**: Why this cannot wait until after launch (must be Critical or High severity)
2. **Impact assessment**: What breaks if we do not merge this change
3. **Blast radius**: Files changed, modules affected, downstream dependencies
4. **Test evidence**: All existing tests pass; new regression test included
5. **Rollback plan**: How to revert if the fix introduces a regression
6. **CI evidence**: All required gates pass on the PR (see `GATE_INVENTORY.md`)

### Approval Flow

```
Developer opens freeze-exception issue
  -> Security Lead reviews severity (< 4 hours SLA)
  -> Protocol Lead reviews blast radius (< 4 hours SLA)
  -> QA Lead confirms test evidence (< 4 hours SLA)
  -> Release Manager makes final merge/reject decision
  -> If approved: PR merged with `freeze-exception-approved` label
  -> If rejected: Change deferred to post-launch hotfix
```

### Evidence Artifacts

Every approved freeze exception must produce:

- Signed approval from RC-01 quorum (GitHub review approvals on the PR)
- CI gate evidence screenshot or link to passing workflow run
- Post-merge verification: release branch CI passes end-to-end

---

## 4. Branch Strategy During Freeze

### Testnet Release

- Release branch: `release/testnet-v1.0`
- Cut from `main` at soft freeze start (March 25, 2026)
- Only cherry-picks from `main` during soft freeze (with PR review)
- No cherry-picks during hard freeze without RC-01 approval

### Mainnet Release

- Release branch: `release/mainnet-v1.0`
- Cut from `main` at feature freeze (October 15, 2026)
- Cherry-picks allowed during soft freeze with standard PR review
- No cherry-picks during hard freeze without RC-01 approval

---

## 5. Post-Freeze / Post-Launch

- Hotfix branch: `hotfix/mainnet-v1.0.x` cut from the release tag
- Hotfix merges require RC-01 approval (same process as freeze exceptions)
- All hotfixes must be back-merged to `main` within 24 hours
- Post-mortem required for any hotfix within 7 days of launch

---

## 6. Communication

- Freeze announcements posted to `#release-engineering` channel 48 hours before each phase
- Daily freeze status updates during hard freeze
- All freeze exceptions logged in this repository under `docs/operations/freeze-exceptions/`

---

## 7. References

- Gate inventory: [`docs/operations/GATE_INVENTORY.md`](GATE_INVENTORY.md)
- Branch protection checks: [`.github/branch-protection/required-checks.json`](../../.github/branch-protection/required-checks.json)
- CI/CD gates: [`docs/operations/ci-cd-gates.md`](ci-cd-gates.md)
- Audit status: [`docs/audits/STATUS.md`](../audits/STATUS.md)
