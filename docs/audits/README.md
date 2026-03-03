# Security Audit Evidence

This directory is the source of truth for third-party audit evidence referenced by this repository.

## Current Status

- Status: `IN_PROGRESS`
- Scope: Ethereum contracts (`/contracts/ethereum`) and consensus-critical vote-extension paths
- Latest update: `2026-02-14`
- Baseline report: `/audits/reports/2026-02-14-preaudit-baseline.md`

## Required Evidence Before Mainnet

1. Signed Statement of Work (SoW) from the auditor
2. Audit report PDF(s) with version + commit hash scope
3. Machine-readable findings list (JSON/CSV/Markdown)
4. Remediation report mapping findings to commits
5. Auditor sign-off that critical/high findings are resolved or accepted with risk notes

## Repository Convention

- Put final audit reports under `/audits/reports/`
- Start from `/audits/reports/SIGNED_REPORT_TEMPLATE.md` for completed reports
- Put remediation mappings under `/audits/remediation/`
- Keep `/audits/STATUS.md` updated as findings move from open to closed
- For any report marked `Completed` in `/audits/STATUS.md`, include one of:
  - `Signed-Off: yes` (or `true` / `approved`)
  - `Auditor-Signature: <reference>`

## Deployment Gate

- `make audit-signoff-check` validates that both `/contracts/ethereum` and `Consensus + vote extensions` have at least one `Completed` row in `/audits/STATUS.md` with valid signed metadata and a real report path.
- The staging/canary/production deployment workflow now runs this gate before any cluster rollout.

If an audit is not complete, do not claim "passed" status in badges or release notes.
