# GitHub Configuration

This directory contains the repository-wide GitHub configuration for Aethelred.

## What Lives Here

- `workflows/`: CI, security, release, deployment, SDK, docs, and launch gates
- `ISSUE_TEMPLATE/`: issue intake templates for bugs and feature requests
- `PULL_REQUEST_TEMPLATE.md`: pull request checklist and contributor expectations
- `branch-protection/`: required check definitions used to keep launch branches honest
- `dependabot.yml`: dependency update policy

## Operating Rules

- Treat workflow changes as production-affecting changes.
- Keep required gates aligned with `docs/operations/GATE_INVENTORY.md`.
- Do not merge workflow or branch-protection changes without corresponding evidence.
- Release and launch changes must follow `docs/operations/FREEZE_POLICY.md`.

## Maintainers

Primary owners for this directory are Release Engineering, Security, and Core Protocol.

## Related Docs

- `docs/operations/GATE_INVENTORY.md`
- `docs/operations/FREEZE_POLICY.md`
- `docs/VALIDATOR_RUNBOOK.md`
