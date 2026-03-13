# Security Audit Evidence

This directory is the public evidence index referenced by Aethelred GitHub
repositories and release notes.

## Current Status

- Internal full-protocol review: completed
- External consultant VRF review: completed
- External mainnet audits for contracts and consensus-critical paths: in progress
- Status tracker: [STATUS.md](STATUS.md)

## Required Evidence Before Mainnet

1. Signed statement of work or engagement record
2. Audit report(s) with scoped commit or tag references
3. Machine-readable findings list or remediation tracker
4. Evidence linking findings to code or configuration fixes
5. Auditor or reviewer sign-off for completed scopes

## Repository Convention

- Store reports under `docs/audits/reports/`
- Store remediation mappings under `docs/audits/remediation/`
- Keep [STATUS.md](STATUS.md) current when findings or sign-off status changes
- Do not use badges or release notes that imply a completed external audit until
  signed evidence is published here

## Release Note Rule

If an audit is not complete, release notes may describe the audit as "in
progress" or "active", but must not imply final sign-off.
